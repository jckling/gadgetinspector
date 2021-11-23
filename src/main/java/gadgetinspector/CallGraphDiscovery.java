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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CallGraphDiscovery {
    private static final Logger LOGGER = LoggerFactory.getLogger(CallGraphDiscovery.class);

    // 调用关系信息：方法所属类名，方法名，方法描述符，被调方法所属类名，被调方法名，被调方法描述符，方法参数索引，方法参数对象的字段名称，被调方法参数索引
    private final Set<GraphCall> discoveredCalls = new HashSet<>();

    /**
     * 分析调用关系，即被调方法的参数是否会被（调用者）方法的参数所影响
     *
     * @param classResourceEnumerator 类枚举器
     * @param config                  配置
     * @throws IOException
     */
    public void discover(final ClassResourceEnumerator classResourceEnumerator, GIConfig config) throws IOException {
        // 加载方法信息
        Map<MethodReference.Handle, MethodReference> methodMap = DataLoader.loadMethods();
        // 加载类信息
        Map<ClassReference.Handle, ClassReference> classMap = DataLoader.loadClasses();
        // 加载继承信息（inheritanceMap：子类->父类集合，subClassMap：父类->子类集合）
        InheritanceMap inheritanceMap = InheritanceMap.load();
        // 加载数据流信息：方法->传递污染的参数索引
        Map<MethodReference.Handle, Set<Integer>> passthroughDataflow = PassthroughDiscovery.load();

        // 序列化决策者
        SerializableDecider serializableDecider = config.getSerializableDecider(methodMap, inheritanceMap);

        // 遍历所有的类
        for (ClassResourceEnumerator.ClassResource classResource : classResourceEnumerator.getAllClasses()) {
            try (InputStream in = classResource.getInputStream()) { // 读取类文件
                ClassReader cr = new ClassReader(in);   // 创建 ClassReader，后续调用 accept 方法解析类文件
                try {
                    // 判断被调方法的参数是否会被调用者方法的参数所影响
                    // 重写方法的调用顺序（没有重写的调用默认方法）：visit -> visitMethod -> visitOuterClass -> visitInnerClass -> visitEnd
                    cr.accept(new ModelGeneratorClassVisitor(classMap, inheritanceMap, passthroughDataflow, serializableDecider, Opcodes.ASM6),
                            ClassReader.EXPAND_FRAMES);
                } catch (Exception e) {
                    LOGGER.error("Error analyzing: " + classResource.getName(), e);
                }
            }
        }
    }

    /**
     * 使用工厂方法存储调用关系信息
     *
     * @throws IOException
     */
    public void save() throws IOException {
        DataLoader.saveData(Paths.get("callgraph.dat"), new GraphCall.Factory(), discoveredCalls);
    }

    private class ModelGeneratorClassVisitor extends ClassVisitor {

        private final Map<ClassReference.Handle, ClassReference> classMap;              // 类信息
        private final InheritanceMap inheritanceMap;                                    // 继承信息
        private final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;    // 数据流信息
        private final SerializableDecider serializableDecider;                          // 序列化决策者

        public ModelGeneratorClassVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                                          InheritanceMap inheritanceMap,
                                          Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,
                                          SerializableDecider serializableDecider, int api) {
            super(api); // ASM API 版本
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.passthroughDataflow = passthroughDataflow;
            this.serializableDecider = serializableDecider;
        }

        private String name;            // 类名
        private String signature;       // 签名
        private String superName;       // 父类名
        private String[] interfaces;    // 接口

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            // 记录类的相关信息
            this.name = name;
            this.signature = signature;
            this.superName = superName;
            this.interfaces = interfaces;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc,
                                         String signature, String[] exceptions) {

            // 调用父类方法，返回新的方法观察者
            // 如果类观察者的 cv 变量为空，则返回 null，否则返回 cv.visitMethod
            MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);

            // 创建方法访问者，判断方法参数与被调用方法参数的传递关系
            // 重写方法的调用顺序（没有重写的调用默认方法）:visitCode -> visitFieldInsn -> visitMethodInsn
            ModelGeneratorMethodVisitor modelGeneratorMethodVisitor = new ModelGeneratorMethodVisitor(classMap,
                    inheritanceMap, passthroughDataflow, serializableDecider, api, mv, this.name, access, name, desc, signature, exceptions);

            // 简化代码分析，删除 JSR 指令并内联引用的子例程
            return new JSRInlinerAdapter(modelGeneratorMethodVisitor, access, name, desc, signature, exceptions);
        }

        @Override
        public void visitOuterClass(String owner, String name, String desc) {   // 访问类的外围类（如果有）
            // TODO: Write some tests to make sure we can ignore this
            super.visitOuterClass(owner, name, desc);
        }

        @Override
        public void visitInnerClass(String name, String outerName, String innerName, int access) {  // 访问内部类，该内部类不一定是被访问的类的成员
            // TODO: Write some tests to make sure we can ignore this
            super.visitInnerClass(name, outerName, innerName, access);
        }

        @Override
        public void visitEnd() {
            super.visitEnd();
        }
    }

    private class ModelGeneratorMethodVisitor extends TaintTrackingMethodVisitor<String> {

        private final Map<ClassReference.Handle, ClassReference> classMap;
        private final InheritanceMap inheritanceMap;
        private final SerializableDecider serializableDecider;
        private final String owner;
        private final int access;
        private final String name;
        private final String desc;

        public ModelGeneratorMethodVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                                           InheritanceMap inheritanceMap,
                                           Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,
                                           SerializableDecider serializableDecider, final int api, final MethodVisitor mv,
                                           final String owner, int access, String name, String desc, String signature,
                                           String[] exceptions) {
            super(inheritanceMap, passthroughDataflow, api, mv, owner, access, name, desc, signature, exceptions);
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.serializableDecider = serializableDecider;
            this.owner = owner;
            this.access = access;
            this.name = name;
            this.desc = desc;
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
                // 使用 arg 前缀来表示方法入参，后续用于判断是否为目标调用方法的入参
                setLocalTaint(localIndex, "arg" + argIndex);
                localIndex += 1;
                argIndex += 1;
            }

            // 遍历参数，根据描述符得出参数类型（占用空间大小）
            for (Type argType : Type.getArgumentTypes(desc)) {
                // 调用 TaintTrackingMethodVisitor.setLocalTaint 添加到本地变量表
                setLocalTaint(localIndex, "arg" + argIndex);
                localIndex += argType.getSize();
                argIndex += 1;
            }
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
                        Set<String> newTaint = new HashSet<>();
                        if (!Boolean.TRUE.equals(isTransient)) {
                            for (String s : getStackTaint(0)) {
                                newTaint.add(s + "." + name);   // 拼接名称
                            }
                        }
                        // 调用 TaintTrackingMethodVisitor.visitFieldInsn 进行出/入栈操作
                        super.visitFieldInsn(opcode, owner, name, desc);

                        // 调用 TaintTrackingMethodVisitor.setStackTaint 将栈顶设置为 newTaint
                        setStackTaint(0, newTaint);
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
            // 获取被调用方法的参数和类型，非静态方法需要把实例类型放在第一个元素
            // 根据描述符得出被调用方法的参数类型（占用空间大小）
            Type[] argTypes = Type.getArgumentTypes(desc);

            // 非静态方法的第一个参数是对象本身，即 this
            if (opcode != Opcodes.INVOKESTATIC) {   // 非静态方法的第一个参数是实例
                Type[] extendedArgTypes = new Type[argTypes.length + 1];
                System.arraycopy(argTypes, 0, extendedArgTypes, 1, argTypes.length);
                extendedArgTypes[0] = Type.getObjectType(owner);    // 对象类型
                argTypes = extendedArgTypes;
            }

            switch (opcode) {
                case Opcodes.INVOKESTATIC:      // 调用静态方法
                case Opcodes.INVOKEVIRTUAL:     // 调用实例方法
                case Opcodes.INVOKESPECIAL:     // 调用超类构造方法，实例初始化方法，私有方法
                case Opcodes.INVOKEINTERFACE:   // 调用接口方法
                    int stackIndex = 0;
                    // 被调用方法的操作数栈
                    for (int i = 0; i < argTypes.length; i++) {
                        // 最右边的参数，就是最后入栈，即在栈顶
                        int argIndex = argTypes.length - 1 - i; // 参数索引
                        Type type = argTypes[argIndex]; // 参数类型

                        // 参数从右往左入栈，因此最右边的参数在栈底
                        Set<String> taint = getStackTaint(stackIndex);
                        if (taint.size() > 0) { // 如果存在能够传递污染的参数
                            // 遍历参数
                            for (String argSrc : taint) {
                                if (!argSrc.substring(0, 3).equals("arg")) {
                                    throw new IllegalStateException("Invalid taint arg: " + argSrc);
                                }
                                // arg数字.字段名称
                                int dotIndex = argSrc.indexOf('.'); // 分隔位置
                                int srcArgIndex;    // 第几个参数
                                String srcArgPath;
                                if (dotIndex == -1) {
                                    srcArgIndex = Integer.parseInt(argSrc.substring(3));
                                    srcArgPath = null;  // 没有名称
                                } else {
                                    srcArgIndex = Integer.parseInt(argSrc.substring(3, dotIndex));
                                    srcArgPath = argSrc.substring(dotIndex + 1);  // 字段名称
                                }

                                // 记录参数流动关系
                                // argIndex：当前方法参数索引；srcArgIndex：对应上一级方法的参数索引
                                discoveredCalls.add(new GraphCall(
                                        new MethodReference.Handle(new ClassReference.Handle(this.owner), this.name, this.desc),
                                        new MethodReference.Handle(new ClassReference.Handle(owner), name, desc),
                                        srcArgIndex,
                                        srcArgPath,
                                        argIndex));
                            }
                        }
                        // 往左一个参数
                        stackIndex += type.getSize();
                    }
                    break;
                default:
                    throw new IllegalStateException("Unsupported opcode: " + opcode);
            }

            // 调用 TaintTrackingMethodVisitor.visitMethodInsn 执行出/入栈操作
            super.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }

    public static void main(String[] args) throws Exception {
        ClassLoader classLoader = Util.getWarClassLoader(Paths.get(args[0]));

        CallGraphDiscovery callGraphDiscovery = new CallGraphDiscovery();
        callGraphDiscovery.discover(new ClassResourceEnumerator(classLoader), new JavaDeserializationConfig());
        callGraphDiscovery.save();
    }
}
