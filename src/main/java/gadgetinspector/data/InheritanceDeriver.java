package gadgetinspector.data;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class InheritanceDeriver {
    private static final Logger LOGGER = LoggerFactory.getLogger(InheritanceDeriver.class);

    /**
     * 获取继承信息：子类->父类集合、父类->子类集合
     *
     * @param classMap 类信息
     * @return
     */
    public static InheritanceMap derive(Map<ClassReference.Handle, ClassReference> classMap) {
        LOGGER.debug("Calculating inheritance for " + (classMap.size()) + " classes...");
        Map<ClassReference.Handle, Set<ClassReference.Handle>> implicitInheritance = new HashMap<>();
        // 遍历所有类
        for (ClassReference classReference : classMap.values()) {
            if (implicitInheritance.containsKey(classReference.getHandle())) {
                throw new IllegalStateException("Already derived implicit classes for " + classReference.getName());
            }
            Set<ClassReference.Handle> allParents = new HashSet<>();

            // 获取 classReference 的所有父类、超类、接口类
            getAllParents(classReference, classMap, allParents);

            // 添加缓存：类名->所有的父类、超类、接口类
            implicitInheritance.put(classReference.getHandle(), allParents);
        }
        return new InheritanceMap(implicitInheritance);
    }

    /**
     * 获取目标类的所有父类、超类、接口类
     *
     * @param classReference 目标类
     * @param classMap       类信息
     * @param allParents     父类、超类、接口类
     */
    private static void getAllParents(ClassReference classReference, Map<ClassReference.Handle, ClassReference> classMap, Set<ClassReference.Handle> allParents) {
        Set<ClassReference.Handle> parents = new HashSet<>();   // 已知当前父类和接口
        // 把当前 classReference 类的所有父类添加到 parents
        if (classReference.getSuperClass() != null) {
            parents.add(new ClassReference.Handle(classReference.getSuperClass()));
        }
        // 把当前 classReference 类实现的所有接口添加到 parents
        for (String iface : classReference.getInterfaces()) {
            parents.add(new ClassReference.Handle(iface));
        }

        // 从类数据集合中，遍历找出 classReference 的直接父类/接口
        for (ClassReference.Handle immediateParent : parents) { // 查找直接父类信息
            ClassReference parentClassReference = classMap.get(immediateParent);
            if (parentClassReference == null) {
                LOGGER.debug("No class id for " + immediateParent.getName());
                continue;
            }

            // 添加到 allParents 父类集合中
            allParents.add(parentClassReference.getHandle());
            // 递归查找，直到把 classReference 类的所有父类、超类、接口类都添加到 allParents
            getAllParents(parentClassReference, classMap, allParents);  // 递归查找父类的父类
        }
    }

    /**
     * 获取类的所有重写方法
     *
     * @param inheritanceMap 继承关系
     * @param methodMap      方法信息
     * @return
     */
    public static Map<MethodReference.Handle, Set<MethodReference.Handle>> getAllMethodImplementations(
            InheritanceMap inheritanceMap, Map<MethodReference.Handle, MethodReference> methodMap) {
        // 存储类的方法，类->方法集合
        Map<ClassReference.Handle, Set<MethodReference.Handle>> methodsByClass = new HashMap<>();
        // 遍历方法信息，获取类->方法集合
        for (MethodReference.Handle method : methodMap.keySet()) {
            ClassReference.Handle classReference = method.getClassReference();  // 获取类
            if (!methodsByClass.containsKey(classReference)) {  // 避免重复
                Set<MethodReference.Handle> methods = new HashSet<>();  // 存储方法
                methods.add(method);
                methodsByClass.put(classReference, methods);
            } else {
                methodsByClass.get(classReference).add(method); // 添加方法
            }
        }

        // 存储继承关系，父类->子类集合
        Map<ClassReference.Handle, Set<ClassReference.Handle>> subClassMap = new HashMap<>();
        for (Map.Entry<ClassReference.Handle, Set<ClassReference.Handle>> entry : inheritanceMap.entrySet()) {
            // 从 子类->父类集合 中取出父类
            for (ClassReference.Handle parent : entry.getValue()) {
                if (!subClassMap.containsKey(parent)) { // 避免重复
                    Set<ClassReference.Handle> subClasses = new HashSet<>();    // 存储子类
                    subClasses.add(entry.getKey());
                    subClassMap.put(parent, subClasses);
                } else {
                    subClassMap.get(parent).add(entry.getKey());    // 添加子类
                }
            }
        }

        // 查找重写方法
        Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap = new HashMap<>();
        // 遍历方法集合
        for (MethodReference method : methodMap.values()) {
            // Static methods cannot be overriden
            if (method.isStatic()) {    // 静态方法不能被重写
                continue;
            }

            // 存储重写方法
            Set<MethodReference.Handle> overridingMethods = new HashSet<>();
            Set<ClassReference.Handle> subClasses = subClassMap.get(method.getClassReference());    // 方法所属类的子类集合
            if (subClasses != null) {
                // 遍历子类
                for (ClassReference.Handle subClass : subClasses) {
                    // This class extends ours; see if it has a matching method
                    Set<MethodReference.Handle> subClassMethods = methodsByClass.get(subClass); // 类的方法集合
                    if (subClassMethods != null) {
                        for (MethodReference.Handle subClassMethod : subClassMethods) {
                            // 判断方法名称和描述符是否相等
                            if (subClassMethod.getName().equals(method.getName()) && subClassMethod.getDesc().equals(method.getDesc())) {
                                overridingMethods.add(subClassMethod);
                            }
                        }
                    }
                }
            }

            // 如果存在重写方法，则保存到 methodImplMap 中
            if (overridingMethods.size() > 0) {
                methodImplMap.put(method.getHandle(), overridingMethods);
            }
        }

        return methodImplMap;
    }
}
