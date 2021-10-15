package gadgetinspector.data;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.*;

public class InheritanceMap {
    private final Map<ClassReference.Handle, Set<ClassReference.Handle>> inheritanceMap;    // 子类->父类集合
    private final Map<ClassReference.Handle, Set<ClassReference.Handle>> subClassMap;       // 父类->子类集合

    /**
     * 构造函数，从 `子类->父类集合` 得出 `父类->子类集合`
     *
     * @param inheritanceMap 继承关系
     */
    public InheritanceMap(Map<ClassReference.Handle, Set<ClassReference.Handle>> inheritanceMap) {
        this.inheritanceMap = inheritanceMap;
        subClassMap = new HashMap<>();
        for (Map.Entry<ClassReference.Handle, Set<ClassReference.Handle>> entry : inheritanceMap.entrySet()) {
            ClassReference.Handle child = entry.getKey();
            for (ClassReference.Handle parent : entry.getValue()) {
                // 如果 key 不存在，则创建，最后返回 value
                subClassMap.computeIfAbsent(parent, k -> new HashSet<>()).add(child);
            }
        }
    }

    public Set<Map.Entry<ClassReference.Handle, Set<ClassReference.Handle>>> entrySet() {
        return inheritanceMap.entrySet();
    }

    /**
     * 返回父类集合
     *
     * @param clazz 目标类
     * @return
     */
    public Set<ClassReference.Handle> getSuperClasses(ClassReference.Handle clazz) {
        Set<ClassReference.Handle> parents = inheritanceMap.get(clazz);
        if (parents == null) {
            return null;
        }
        return Collections.unmodifiableSet(parents);
    }

    /**
     * 判断目标父类是否为目标子类的父类
     *
     * @param clazz      目标子类
     * @param superClass 目标父类
     * @return
     */
    public boolean isSubclassOf(ClassReference.Handle clazz, ClassReference.Handle superClass) {
        Set<ClassReference.Handle> parents = inheritanceMap.get(clazz);
        if (parents == null) {
            return false;
        }
        return parents.contains(superClass);
    }

    /**
     * 返回子类集合
     *
     * @param clazz 目标类
     * @return
     */
    public Set<ClassReference.Handle> getSubClasses(ClassReference.Handle clazz) {
        Set<ClassReference.Handle> subClasses = subClassMap.get(clazz);
        if (subClasses == null) {
            return null;
        }
        return Collections.unmodifiableSet(subClasses);
    }

    /**
     * 存储继承关系：子类->父类集合
     *
     * @throws IOException
     */
    public void save() throws IOException {
        // inheritanceMap.dat 数据格式：
        // 类名 父类或超类或接口类1 父类或超类或接口类2 父类或超类或接口类3 ...
        DataLoader.saveData(Paths.get("inheritanceMap.dat"), new InheritanceMapFactory(), inheritanceMap.entrySet());
    }

    /**
     * 加载继承关系
     *
     * @return
     * @throws IOException
     */
    public static InheritanceMap load() throws IOException {
        Map<ClassReference.Handle, Set<ClassReference.Handle>> inheritanceMap = new HashMap<>();
        for (Map.Entry<ClassReference.Handle, Set<ClassReference.Handle>> entry : DataLoader.loadData(
                Paths.get("inheritanceMap.dat"), new InheritanceMapFactory())) {
            inheritanceMap.put(entry.getKey(), entry.getValue());
        }
        return new InheritanceMap(inheritanceMap);
    }

    /**
     * 数据工厂接口实现
     */
    private static class InheritanceMapFactory implements DataFactory<Map.Entry<ClassReference.Handle, Set<ClassReference.Handle>>> {
        @Override
        public Map.Entry<ClassReference.Handle, Set<ClassReference.Handle>> parse(String[] fields) {
            ClassReference.Handle clazz = new ClassReference.Handle(fields[0]);
            Set<ClassReference.Handle> superClasses = new HashSet<>();
            for (int i = 1; i < fields.length; i++) {
                superClasses.add(new ClassReference.Handle(fields[i]));
            }
            return new AbstractMap.SimpleEntry<>(clazz, superClasses);
        }

        @Override
        public String[] serialize(Map.Entry<ClassReference.Handle, Set<ClassReference.Handle>> obj) {
            final String[] fields = new String[obj.getValue().size() + 1];
            fields[0] = obj.getKey().getName();
            int i = 1;
            for (ClassReference.Handle handle : obj.getValue()) {
                fields[i++] = handle.getName();
            }
            return fields;
        }
    }
}
