package gadgetinspector;

import gadgetinspector.data.ClassReference;
import gadgetinspector.data.DataLoader;
import gadgetinspector.data.InheritanceDeriver;
import gadgetinspector.data.MethodReference;
import org.objectweb.asm.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MethodDiscovery {

    private static final Logger LOGGER = LoggerFactory.getLogger(MethodDiscovery.class);

    private final List<ClassReference> discoveredClasses = new ArrayList<>();   // 类信息
    private final List<MethodReference> discoveredMethods = new ArrayList<>();  // 方法信息

    /**
     * 使用工厂方法存储数据
     *
     * @throws IOException
     */
    public void save() throws IOException {

        // classes.dat 数据格式：
        // 类名 父类名 接口A,接口B,接口C 是否为接口 字段1!字段1描述符!字段1类型!字段2!字段2描述符!字段2类型
        DataLoader.saveData(Paths.get("classes.dat"), new ClassReference.Factory(), discoveredClasses);

        // methods.dat 数据格式：
        // 类名 方法名 方法描述符 是否为静态方法
        DataLoader.saveData(Paths.get("methods.dat"), new MethodReference.Factory(), discoveredMethods);

        // 形成 类名(ClassReference.Handle)->类(ClassReference) 的映射关系
        Map<ClassReference.Handle, ClassReference> classMap = new HashMap<>();
        for (ClassReference clazz : discoveredClasses) {
            classMap.put(clazz.getHandle(), clazz);
        }

        // 对上面的类信息进行递归整合，得到 `子类->父类集合` 的继承信息，保存到 inheritanceMap.dat
        InheritanceDeriver.derive(classMap).save();
    }

    /**
     * 使用访问者记录类信息和方法信息
     *
     * @param classResourceEnumerator 类枚举器
     * @throws Exception
     */
    public void discover(final ClassResourceEnumerator classResourceEnumerator) throws Exception {
        // 遍历所有的类
        for (ClassResourceEnumerator.ClassResource classResource : classResourceEnumerator.getAllClasses()) {
            try (InputStream in = classResource.getInputStream()) { // 读取类文件
                ClassReader cr = new ClassReader(in);   // 创建 ClassReader，后续调用 accept 方法解析类文件
                try {
                    // 继承 asm 的 ClassVisitor(MethodVisitor) 实现对类文件的观察，记录类信息和方法信息
                    // 重写方法的调用顺序（没有重写的调用默认方法）：visit -> visitField -> visitMethod -> visitEnd
                    cr.accept(new MethodDiscoveryClassVisitor(), ClassReader.EXPAND_FRAMES);    // 以扩展格式访问堆栈映射帧
                } catch (Exception e) {
                    LOGGER.error("Exception analyzing: " + classResource.getName(), e);
                }
            }
        }
    }

    // 类访问者
    private class MethodDiscoveryClassVisitor extends ClassVisitor {

        private String name;            // 类的内部名称
        private String superName;       // 父类的内部名称
        private String[] interfaces;    // 类接口的内部名称
        boolean isInterface;            // 是否为接口
        private List<ClassReference.Member> members;    // 类的所有字段
        private ClassReference.Handle classHandle;      // 引用

        private MethodDiscoveryClassVisitor() throws SQLException {
            super(Opcodes.ASM6);
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {  // 类访问开始（调用的第一个方法）
            // 记录类信息
            this.name = name;
            this.superName = superName;
            this.interfaces = interfaces;
            this.isInterface = (access & Opcodes.ACC_INTERFACE) != 0;
            this.members = new ArrayList<>();   // 字段信息（成员）
            this.classHandle = new ClassReference.Handle(name); // 当前类

            // 调用父类方法
            super.visit(version, access, name, signature, superName, interfaces);
        }

        public FieldVisitor visitField(int access, String name, String desc,    // 访问字段
                                       String signature, Object value) {
            if ((access & Opcodes.ACC_STATIC) == 0) { // 跳过静态成员
                Type type = Type.getType(desc); // 类型
                String typeName;
                if (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY) {    // 对象或数组
                    typeName = type.getInternalName();  // 内部名称
                } else {
                    typeName = type.getDescriptor();    // 描述符
                }
                // 记录字段信息，保存到 members
                members.add(new ClassReference.Member(name, access, new ClassReference.Handle(typeName)));
            }

            // 调用父类方法
            return super.visitField(access, name, desc, signature, value);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) { // 访问方法
            boolean isStatic = (access & Opcodes.ACC_STATIC) != 0;  // 是否为静态方法

            // 记录方法信息，保存到 discoveredMethods
            discoveredMethods.add(new MethodReference(
                    classHandle,    // 所属类
                    name,
                    desc,
                    isStatic));

            // 调用父类方法
            return super.visitMethod(access, name, desc, signature, exceptions);
        }

        @Override
        public void visitEnd() {    // 类访问结束（调用的最后一个方法）
            ClassReference classReference = new ClassReference(
                    name,
                    superName,
                    interfaces,
                    isInterface,
                    members.toArray(new ClassReference.Member[members.size()])); // 把所有找到的字段封装

            // 记录类信息，保存到 discoveredClasses
            discoveredClasses.add(classReference);

            // 调用父类方法
            super.visitEnd();
        }

    }

    public static void main(String[] args) throws Exception {
        ClassLoader classLoader = Util.getWarClassLoader(Paths.get(args[0]));

        MethodDiscovery methodDiscovery = new MethodDiscovery();
        methodDiscovery.discover(new ClassResourceEnumerator(classLoader));
        methodDiscovery.save();
    }
}
