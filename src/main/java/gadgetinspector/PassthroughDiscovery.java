package gadgetinspector;

import gadgetinspector.config.GIConfig;
import gadgetinspector.config.JavaDeserializationConfig;
import gadgetinspector.data.*;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.JSRInlinerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.*;

public class PassthroughDiscovery {

    private static final Logger LOGGER = LoggerFactory.getLogger(PassthroughDiscovery.class);

    // 方法调用信息：方法->调用的方法集合
    private final Map<MethodReference.Handle, Set<MethodReference.Handle>> methodCalls = new HashMap<>();
    // 数据流信息：方法->传递污染的参数索引
    private Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;

    /**
     * 得到每个方法能够传递污染的参数（索引）集合
     *
     * @param classResourceEnumerator 类枚举器
     * @param config                  配置
     * @throws IOException
     */
    public void discover(final ClassResourceEnumerator classResourceEnumerator, final GIConfig config) throws IOException {
        // 加载方法信息
        Map<MethodReference.Handle, MethodReference> methodMap = DataLoader.loadMethods();
        // 加载类信息
        Map<ClassReference.Handle, ClassReference> classMap = DataLoader.loadClasses();
        // 加载继承信息（inheritanceMap：子类->父类集合，subClassMap：父类->子类集合）
        InheritanceMap inheritanceMap = InheritanceMap.load();

        // 搜索方法的调用关系（methodCalls）并得到 `类名->类资源` 映射集合
        Map<String, ClassResourceEnumerator.ClassResource> classResourceByName = discoverMethodCalls(classResourceEnumerator);

        // 对方法的调用关系进行逆拓扑排序
        List<MethodReference.Handle> sortedMethods = topologicallySortMethodCalls();

        // 分析每个方法能够传递污染的参数
        // classResourceByName  类资源集合
        // classMap             类信息
        // inheritanceMap       继承信息
        // sortedMethods        方法集合（经逆拓扑排序）
        // SerializableDecider  序列化决策者
        passthroughDataflow = calculatePassthroughDataflow(classResourceByName, classMap, inheritanceMap, sortedMethods,
                config.getSerializableDecider(methodMap, inheritanceMap));
    }


    /**
     * 搜索方法调用信息：方法->被调用方法集合
     * 存储类资源映射信息：类名->类资源
     *
     * @param classResourceEnumerator 类枚举器
     * @return
     * @throws IOException
     */
    private Map<String, ClassResourceEnumerator.ClassResource> discoverMethodCalls(final ClassResourceEnumerator classResourceEnumerator) throws IOException {
        // 类名->类资源
        Map<String, ClassResourceEnumerator.ClassResource> classResourcesByName = new HashMap<>();

        // 遍历所有的类
        for (ClassResourceEnumerator.ClassResource classResource : classResourceEnumerator.getAllClasses()) {
            try (InputStream in = classResource.getInputStream()) { // 读取类文件
                ClassReader cr = new ClassReader(in);   // 创建 ClassReader，后续调用 accept 方法解析类文件
                try {
                    // 继承 asm 的 ClassVisitor(MethodVisitor) 实现对类文件的观察
                    MethodCallDiscoveryClassVisitor visitor = new MethodCallDiscoveryClassVisitor(Opcodes.ASM6);
                    // 重写方法的调用顺序（没有重写的调用默认方法）：visit -> visitMethod -> visitEnd
                    cr.accept(visitor, ClassReader.EXPAND_FRAMES);
                    // 存储 `类名(String)->类资源(ClassResource)` 的映射关系
                    classResourcesByName.put(visitor.getName(), classResource);
                } catch (Exception e) {
                    LOGGER.error("Error analyzing: " + classResource.getName(), e);
                }
            }
        }
        return classResourcesByName;
    }

    /**
     * 对方法的调用关系进行逆拓扑排序（按名称逆序）
     *
     * @return
     */
    private List<MethodReference.Handle> topologicallySortMethodCalls() {
        // 拷贝方法调用的方法集合
        Map<MethodReference.Handle, Set<MethodReference.Handle>> outgoingReferences = new HashMap<>();
        for (Map.Entry<MethodReference.Handle, Set<MethodReference.Handle>> entry : methodCalls.entrySet()) {
            MethodReference.Handle method = entry.getKey(); // 方法
            outgoingReferences.put(method, new HashSet<>(entry.getValue()));    // 调用的方法集合
        }

        // Topological sort methods
        LOGGER.debug("Performing topological sort...");
        Set<MethodReference.Handle> dfsStack = new HashSet<>();     // 避免形成环
        Set<MethodReference.Handle> visitedNodes = new HashSet<>(); // 在调用链出现重合时，避免重复排序
        List<MethodReference.Handle> sortedMethods = new ArrayList<>(outgoingReferences.size());    // 方法调用集合
        for (MethodReference.Handle root : outgoingReferences.keySet()) {
            // 遍历集合中的起始方法，进行递归搜索（DFS），经过逆拓扑排序，调用链的最末端排在最前面，
            // 后续进行参数、返回值、调用链之间的污点传递分析
            dfsTsort(outgoingReferences, sortedMethods, visitedNodes, dfsStack, root);
        }
        LOGGER.debug(String.format("Outgoing references %d, sortedMethods %d", outgoingReferences.size(), sortedMethods.size()));

        // 逆拓扑排序后的方法调用集合
        return sortedMethods;
    }

    /**
     * 分析方法调用集合，获取数据流信息：方法->传递污染的参数索引
     *
     * @param classResourceByName 类资源集合
     * @param classMap            类信息
     * @param inheritanceMap      继承信息
     * @param sortedMethods       所有方法集合（经过逆拓扑排序）
     * @param serializableDecider 序列化决策者
     * @return
     * @throws IOException
     */
    private static Map<MethodReference.Handle, Set<Integer>> calculatePassthroughDataflow(Map<String, ClassResourceEnumerator.ClassResource> classResourceByName,
                                                                                          Map<ClassReference.Handle, ClassReference> classMap,
                                                                                          InheritanceMap inheritanceMap,
                                                                                          List<MethodReference.Handle> sortedMethods,
                                                                                          SerializableDecider serializableDecider) throws IOException {
        // 数据流信息：方法、传递污染的参数索引
        final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow = new HashMap<>();

        // 遍历所有方法
        for (MethodReference.Handle method : sortedMethods) {
            // 跳过 static 静态初始化代码（静态代码块）
            if (method.getName().equals("<clinit>")) {
                continue;
            }

            // 获取方法所属类的类资源
            ClassResourceEnumerator.ClassResource classResource = classResourceByName.get(method.getClassReference().getName());
            try (InputStream inputStream = classResource.getInputStream()) {    // 读取类文件
                ClassReader cr = new ClassReader(inputStream);  // 创建 ClassReader，后续调用 accept 方法解析类文件
                try {
                    /**
                     * classMap             类信息
                     * inheritanceMap       继承信息
                     * passthroughDataflow  数据流信息，初始为空
                     * serializableDecider  序列化决策者
                     * Opcodes.ASM6         ASM API 版本
                     * method               待观察的方法
                     */
                    // 继承 asm 的 ClassVisitor(MethodVisitor) 实现对类文件的观察，记录类信息和方法信息
                    PassthroughDataflowClassVisitor cv = new PassthroughDataflowClassVisitor(classMap, inheritanceMap,
                            passthroughDataflow, serializableDecider, Opcodes.ASM6, method);

                    // 重写方法的调用顺序（没有重写的调用默认方法）：visit -> visitMethod
                    cr.accept(cv, ClassReader.EXPAND_FRAMES);

                    // 缓存方法的哪些参数会影响返回值
                    passthroughDataflow.put(method, cv.getReturnTaint());
                } catch (Exception e) {
                    LOGGER.error("Exception analyzing " + method.getClassReference().getName(), e);
                }
            } catch (IOException e) {
                LOGGER.error("Unable to analyze " + method.getClassReference().getName(), e);
            }
        }
        return passthroughDataflow;
    }

    private class MethodCallDiscoveryClassVisitor extends ClassVisitor {
        public MethodCallDiscoveryClassVisitor(int api) {   // 访问者实现的 ASM API 版本，必须是 Opcodes.ASM4、Opcodes.ASM5、Opcodes.ASM6、Opcodes.ASM7 之一
            super(api);
        }

        private String name = null; // 类名

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            // 调用父类方法
            super.visit(version, access, name, signature, superName, interfaces);

            if (this.name != null) {
                throw new IllegalStateException("ClassVisitor already visited a class!");
            }

            // 记录类名
            this.name = name;
        }

        // 返回类名
        public String getName() {
            return name;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
            // 创建 MethodCallDiscoveryMethodVisitor 观察方法
            MethodCallDiscoveryMethodVisitor modelGeneratorMethodVisitor = new MethodCallDiscoveryMethodVisitor(
                    api, mv, this.name, name, desc);

            // 简化代码分析，删除 JSR 指令并内联引用的子例程
            return new JSRInlinerAdapter(modelGeneratorMethodVisitor, access, name, desc, signature, exceptions);
        }

        @Override
        public void visitEnd() {
            super.visitEnd();
        }
    }

    private class MethodCallDiscoveryMethodVisitor extends MethodVisitor {
        // 方法调用的方法集合
        private final Set<MethodReference.Handle> calledMethods;

        /**
         * 方法访问者构造函数
         *
         * @param api   ASM API 版本
         * @param mv    MethodVisitor 实例
         * @param owner 方法所属类的类名
         * @param name  方法的名称
         * @param desc  方法的描述符
         */
        public MethodCallDiscoveryMethodVisitor(final int api, final MethodVisitor mv,
                                                final String owner, String name, String desc) {
            super(api, mv);

            // 调用的方法集合，初始化
            this.calledMethods = new HashSet<>();
            // 存储到 PassthroughDiscovery 的 methodCalls 中
            methodCalls.put(new MethodReference.Handle(new ClassReference.Handle(owner), name, desc), calledMethods);
        }

        /**
         * 访问方法指令
         * 方法指令是调用方法的指令
         *
         * @param opcode 调用操作码：INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC, INVOKEINTERFACE
         * @param owner  被调用的方法所属类的类名
         * @param name   被调用的方法
         * @param desc   被调用方法的描述符
         * @param itf    被调用的类是否为接口
         */
        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            // 记录调用的方法，存储到 MethodCallDiscoveryMethodVisitor 的 calledMethods 中
            calledMethods.add(new MethodReference.Handle(new ClassReference.Handle(owner), name, desc));
            super.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }

    /**
     * 使用工厂方法存储存储数据流信息
     *
     * @throws IOException
     */
    public void save() throws IOException {
        if (passthroughDataflow == null) {
            throw new IllegalStateException("Save called before discover()");
        }

        DataLoader.saveData(Paths.get("passthrough.dat"), new PassThroughFactory(), passthroughDataflow.entrySet());
    }

    /**
     * 从 passthrough.dat 加载数据流信息
     *
     * @return
     * @throws IOException
     */
    public static Map<MethodReference.Handle, Set<Integer>> load() throws IOException {
        Map<MethodReference.Handle, Set<Integer>> passthroughDataflow = new HashMap<>();
        for (Map.Entry<MethodReference.Handle, Set<Integer>> entry : DataLoader.loadData(Paths.get("passthrough.dat"), new PassThroughFactory())) {
            passthroughDataflow.put(entry.getKey(), entry.getValue());
        }
        return passthroughDataflow;
    }

    /**
     * 数据工厂接口实现
     */
    public static class PassThroughFactory implements DataFactory<Map.Entry<MethodReference.Handle, Set<Integer>>> {

        @Override
        public Map.Entry<MethodReference.Handle, Set<Integer>> parse(String[] fields) {
            ClassReference.Handle clazz = new ClassReference.Handle(fields[0]);
            MethodReference.Handle method = new MethodReference.Handle(clazz, fields[1], fields[2]);

            Set<Integer> passthroughArgs = new HashSet<>();
            for (String arg : fields[3].split(",")) {
                if (arg.length() > 0) {
                    passthroughArgs.add(Integer.parseInt(arg));
                }
            }
            return new AbstractMap.SimpleEntry<>(method, passthroughArgs);
        }

        @Override
        public String[] serialize(Map.Entry<MethodReference.Handle, Set<Integer>> entry) {
            if (entry.getValue().size() == 0) {
                return null;
            }

            final String[] fields = new String[4];
            fields[0] = entry.getKey().getClassReference().getName();   // 方法所属类的类名
            fields[1] = entry.getKey().getName();   // 方法的名称
            fields[2] = entry.getKey().getDesc();   // 方法的描述符

            StringBuilder sb = new StringBuilder();
            for (Integer arg : entry.getValue()) {
                sb.append(Integer.toString(arg));
                sb.append(",");
            }
            fields[3] = sb.toString();  // 参数索引

            return fields;
        }
    }

    /**
     * 逆拓扑排序的具体实现
     *
     * @param outgoingReferences 方法调用的方法集合
     * @param sortedMethods      逆拓扑排序后的方法集合
     * @param visitedNodes       已排序的方法
     * @param stack              栈
     * @param node               待排序的起始方法
     */
    private static void dfsTsort(Map<MethodReference.Handle, Set<MethodReference.Handle>> outgoingReferences,
                                 List<MethodReference.Handle> sortedMethods, Set<MethodReference.Handle> visitedNodes,
                                 Set<MethodReference.Handle> stack, MethodReference.Handle node) {

        // 防止在遍历一条调用链中进入循环
        if (stack.contains(node)) {
            return;
        }

        // 防止对某个方法及被调方法重复排序
        if (visitedNodes.contains(node)) {
            return;
        }

        // 根据起始方法，取出被调用的方法集合
        Set<MethodReference.Handle> outgoingRefs = outgoingReferences.get(node);
        if (outgoingRefs == null) {
            return;
        }

        stack.add(node);    // 入栈，避免递归死循环
        for (MethodReference.Handle child : outgoingRefs) { // 对被调用方法递归进行排序
            dfsTsort(outgoingReferences, sortedMethods, visitedNodes, stack, child);
        }
        stack.remove(node); // 出栈，方法排序完毕
        visitedNodes.add(node);     // 记录已访问的方法，在递归遇到重复方法时可以跳过
        sortedMethods.add(node);    // 记录已排序的方法
    }

    private static class PassthroughDataflowClassVisitor extends ClassVisitor {

        Map<ClassReference.Handle, ClassReference> classMap;    // 类信息
        private final MethodReference.Handle methodToVisit;     // 待观察的方法
        private final InheritanceMap inheritanceMap;            // 继承信息
        private final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;    // 数据流信息：方法->传递污染的参数索引
        private final SerializableDecider serializableDecider;  // 序列化决策者

        private String name;    // 类名
        private PassthroughDataflowMethodVisitor passthroughDataflowMethodVisitor;  // 方法访问者

        public PassthroughDataflowClassVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                                               InheritanceMap inheritanceMap, Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,
                                               SerializableDecider serializableDecider, int api, MethodReference.Handle methodToVisit) {
            super(api); // ASM API 版本
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.methodToVisit = methodToVisit;
            this.passthroughDataflow = passthroughDataflow;
            this.serializableDecider = serializableDecider;
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            this.name = name;   // 记录类名

            // 不是待观察方法的所属类
            if (!this.name.equals(methodToVisit.getClassReference().getName())) {
                throw new IllegalStateException("Expecting to visit " + methodToVisit.getClassReference().getName() + " but instead got " + this.name);
            }
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc,
                                         String signature, String[] exceptions) {
            // 不是待观察方法
            if (!name.equals(methodToVisit.getName()) || !desc.equals(methodToVisit.getDesc())) {
                return null;
            }
            if (passthroughDataflowMethodVisitor != null) {
                throw new IllegalStateException("Constructing passthroughDataflowMethodVisitor twice!");
            }

            // 调用父类方法，返回新的方法观察者
            // 如果类观察者的 cv 变量为空，则返回 null，否则返回 cv.visitMethod
            MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);

            // 创建方法访问者，判断方法返回值与参数的关系
            // 重写方法的调用顺序（没有重写的调用默认方法）：visitCode -> visitInsn -> visitFieldInsn -> visitMethodInsn
            passthroughDataflowMethodVisitor = new PassthroughDataflowMethodVisitor(
                    classMap, inheritanceMap, this.passthroughDataflow, serializableDecider,
                    api, mv, this.name, access, name, desc, signature, exceptions);

            // 简化代码分析，删除 JSR 指令并内联引用的子例程
            return new JSRInlinerAdapter(passthroughDataflowMethodVisitor, access, name, desc, signature, exceptions);
        }

        // 返回能够传递污染的参数索引集合
        public Set<Integer> getReturnTaint() {
            if (passthroughDataflowMethodVisitor == null) {
                throw new IllegalStateException("Never constructed the passthroughDataflowmethodVisitor!");
            }
            return passthroughDataflowMethodVisitor.returnTaint;
        }
    }

    private static class PassthroughDataflowMethodVisitor extends TaintTrackingMethodVisitor<Integer> {

        private final Map<ClassReference.Handle, ClassReference> classMap;              // 类信息
        private final InheritanceMap inheritanceMap;                                    // 继承信息
        private final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;    // 数据流信息：方法->传递污染的参数索引
        private final SerializableDecider serializableDecider;                          // 序列化决策者

        private final int access;               // 访问标志
        private final String desc;              // 描述符
        private final Set<Integer> returnTaint; // 能够传递污染的参数索引集合

        public PassthroughDataflowMethodVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                                                InheritanceMap inheritanceMap, Map<MethodReference.Handle,
                Set<Integer>> passthroughDataflow, SerializableDecider serializableDeciderMap, int api, MethodVisitor mv,
                                                String owner, int access, String name, String desc, String signature, String[] exceptions) {
            super(inheritanceMap, passthroughDataflow, api, mv, owner, access, name, desc, signature, exceptions);
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.passthroughDataflow = passthroughDataflow;
            this.serializableDecider = serializableDeciderMap;
            this.access = access;
            this.desc = desc;
            returnTaint = new HashSet<>();
        }

        @Override
        public void visitCode() {   // 启动对方法代码的访问
            // 调用 TaintTrackingMethodVisitor.visitCode 初始化本地变量表
            super.visitCode();

            // 记录参数到本地变量表 savedVariableState.localVars
            int localIndex = 0;
            int argIndex = 0;
            // 非静态方法，第一个参数（隐式）为对象实例 this
            if ((this.access & Opcodes.ACC_STATIC) == 0) {
                // 调用 TaintTrackingMethodVisitor.setLocalTaint 添加到本地变量表
                setLocalTaint(localIndex, argIndex);
                localIndex += 1;
                argIndex += 1;
            }

            // 遍历参数，根据描述符得出参数类型（占用空间大小）
            for (Type argType : Type.getArgumentTypes(desc)) {
                // 调用 TaintTrackingMethodVisitor.setLocalTaint 添加到本地变量表
                setLocalTaint(localIndex, argIndex);
                localIndex += argType.getSize();
                argIndex += 1;
            }
        }

        @Override
        public void visitInsn(int opcode) { // 访问零操作数指令
            // 方法执行完毕后将从栈返回结果给调用者，因此栈顶即返回值
            // 存储可能被污染的返回值到 returnTaint
            switch (opcode) {
                case Opcodes.IRETURN:   // 从当前方法返回 int
                case Opcodes.FRETURN:   // 从当前方法返回 float
                case Opcodes.ARETURN:   // 从当前方法返回对象引用
                    // 调用 TaintTrackingMethodVisitor.getStackTaint 读取栈顶，大小为 1（32位）
                    returnTaint.addAll(getStackTaint(0));   // 栈空间从内存高位到低位分配空间
                    break;
                case Opcodes.LRETURN:   // 从当前方法返回 long
                case Opcodes.DRETURN:   // 从当前方法返回 double
                    // 调用 TaintTrackingMethodVisitor.getStackTaint 读取栈顶，大小为 2（64位）
                    returnTaint.addAll(getStackTaint(1));
                    break;
                case Opcodes.RETURN:    // 从当前方法返回 void
                    break;
                default:
                    break;
            }

            // 调用 TaintTrackingMethodVisitor.visitInsn 进行出/入栈操作
            super.visitInsn(opcode);
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String desc) {    // 访问字段指令，字段指令是加载或存储对象字段值的指令。
            // 方法执行过程中可能访问对象字段，访问前会进行入栈操作
            switch (opcode) {
                case Opcodes.GETSTATIC: // 获取类的静态字段
                    break;
                case Opcodes.PUTSTATIC: // 设置类的静态字段
                    break;
                case Opcodes.GETFIELD:  // 获取对象字段
                    Type type = Type.getType(desc); // 字段类型
                    if (type.getSize() == 1) {
                        Boolean isTransient = null; // 如果字段被 transient 关键字修饰，则不可序列化

                        // 判断读取的字段所属类是否可序列化，即字段是否可以序列化
                        // If a field type could not possibly be serialized, it's effectively transient
                        if (!couldBeSerialized(serializableDecider, inheritanceMap, new ClassReference.Handle(type.getInternalName()))) {
                            isTransient = Boolean.TRUE;
                        } else {
                            // 若读取的字段所属类可序列化
                            ClassReference clazz = classMap.get(new ClassReference.Handle(owner));
                            while (clazz != null) {
                                // 遍历类的所有字段
                                for (ClassReference.Member member : clazz.getMembers()) {
                                    // 是否为目标字段
                                    if (member.getName().equals(name)) {
                                        // 是否被 transient 关键字修饰
                                        isTransient = (member.getModifiers() & Opcodes.ACC_TRANSIENT) != 0;
                                        break;
                                    }
                                }
                                if (isTransient != null) {
                                    break;
                                }
                                // 若找不到目标字段，则向上查找（超类）
                                clazz = classMap.get(new ClassReference.Handle(clazz.getSuperClass()));
                            }
                        }

                        // 能够传递污染的参数索引集合
                        Set<Integer> taint;
                        if (!Boolean.TRUE.equals(isTransient)) {
                            // 若字段没有被 transient 修饰，则调用 TaintTrackingMethodVisitor.getStackTaint 读取栈顶
                            // 取出的是 this 或某实例对象，即字段所属实例
                            taint = getStackTaint(0);
                        } else {
                            // 否则为空
                            taint = new HashSet<>();
                        }

                        // 调用 TaintTrackingMethodVisitor.visitFieldInsn 进行出/入栈操作
                        super.visitFieldInsn(opcode, owner, name, desc);

                        // 调用 TaintTrackingMethodVisitor.setStackTaint 将栈顶设置为 taint
                        setStackTaint(0, taint);
                        return;
                    }
                    break;
                case Opcodes.PUTFIELD:  // 设置对象字段
                    break;
                default:
                    throw new IllegalStateException("Unsupported opcode: " + opcode);
            }

            // 调用 TaintTrackingMethodVisitor.visitFieldInsn 进行出/入栈操作
            super.visitFieldInsn(opcode, owner, name, desc);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {  // 访问方法指令，方法指令是调用方法的指令。
            // 根据描述符得出被调用方法的参数类型（占用空间大小）
            Type[] argTypes = Type.getArgumentTypes(desc);

            // 非静态方法的第一个参数是对象本身，即 this
            if (opcode != Opcodes.INVOKESTATIC) {
                Type[] extendedArgTypes = new Type[argTypes.length + 1];
                System.arraycopy(argTypes, 0, extendedArgTypes, 1, argTypes.length);
                extendedArgTypes[0] = Type.getObjectType(owner);    // 对象类型
                argTypes = extendedArgTypes;
            }

            // 根据描述符获取被调用方法的返回值类型大小
            int retSize = Type.getReturnType(desc).getSize();
            // 能够传递污染的参数索引集合
            Set<Integer> resultTaint;
            switch (opcode) {
                case Opcodes.INVOKESTATIC:      // 调用静态方法
                case Opcodes.INVOKEVIRTUAL:     // 调用实例方法
                case Opcodes.INVOKESPECIAL:     // 调用超类构造方法，实例初始化方法，私有方法
                case Opcodes.INVOKEINTERFACE:   // 调用接口方法
                    // 模拟操作数栈
                    final List<Set<Integer>> argTaint = new ArrayList<Set<Integer>>(argTypes.length);
                    // 调用方法前先把操作数入栈
                    for (int i = 0; i < argTypes.length; i++) {
                        argTaint.add(null);
                    }

                    // 记录数据起始位置
                    int stackIndex = 0;
                    for (int i = 0; i < argTypes.length; i++) {
                        Type argType = argTypes[i];
                        if (argType.getSize() > 0) {
                            // 根据参数类型的大小，调用 TaintTrackingMethodVisitor.getStackTaint 读取栈中的值
                            // 参数从右往左入栈，这里将参数值拷贝到 argTaint
                            argTaint.set(argTypes.length - 1 - i, getStackTaint(stackIndex + argType.getSize() - 1));
                        }
                        stackIndex += argType.getSize();
                    }

                    // 如果被调用的是构造方法，则认为被调用方法所属类的实例对象本身可以传递污染
                    if (name.equals("<init>")) {
                        // Pass result taint through to original taint set; the initialized object is directly tainted by
                        // parameters
                        resultTaint = argTaint.get(0);  // 从栈顶取出对象，实际上是该对象的参数索引集合
                    } else {
                        resultTaint = new HashSet<>();  // 否则初始化为空
                    }

                    // 经过逆拓扑排序，调用链末端的方法先被访问和判断，即被调用方法已经被判断过
                    // 例如 A->B，判断 A 时 B 已经有判断结果了，并且此时栈中的数据是这样：B对象 B参数
                    Set<Integer> passthrough = passthroughDataflow.get(new MethodReference.Handle(new ClassReference.Handle(owner), name, desc));
                    // 如果被调用方法存在能够传递污染的参数
                    if (passthrough != null) {
                        // 遍历参数索引
                        for (Integer passthroughDataflowArg : passthrough) {
                            // 从栈中获取能够传递污染的参数索引集合，全部添加到 resultTaint
                            resultTaint.addAll(argTaint.get(passthroughDataflowArg));
                        }
                    }
                    break;
                default:
                    throw new IllegalStateException("Unsupported opcode: " + opcode);
            }

            // 调用 TaintTrackingMethodVisitor.visitMethodInsn 执行出/入栈操作，根据预定义的判断规则分析参数索引集合
            super.visitMethodInsn(opcode, owner, name, desc, itf);

            // 返回值不为空
            // 实例对象本身有可能传递污染，因此不能直接根据返回值判断（即不能最先执行这一块）
            if (retSize > 0) {  // 1 或者 2
                // 调用 TaintTrackingMethodVisitor.getStackTaint 将 resultTaint 中的元素合并到参数索引集合中
                // 这里减 1 是因为在 TaintTrackingMethodVisitor.visitMethodInsn 中已经将第一个单位的值设置为其分析得到的参数索引集合
                getStackTaint(retSize - 1).addAll(resultTaint);
            }
        }
    }


    public static void main(String[] args) throws Exception {
        ClassLoader classLoader = Util.getWarClassLoader(Paths.get(args[0]));

        PassthroughDiscovery passthroughDiscovery = new PassthroughDiscovery();
        passthroughDiscovery.discover(new ClassResourceEnumerator(classLoader), new JavaDeserializationConfig());
        passthroughDiscovery.save();
    }
}
