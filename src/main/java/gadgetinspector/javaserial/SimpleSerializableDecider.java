package gadgetinspector.javaserial;

import gadgetinspector.SerializableDecider;
import gadgetinspector.data.ClassReference;
import gadgetinspector.data.InheritanceMap;

import java.util.HashMap;
import java.util.Map;

public class SimpleSerializableDecider implements SerializableDecider {
    private final Map<ClassReference.Handle, Boolean> cache = new HashMap<>();  // 缓存判断结果，类->是否可序列化
    private final InheritanceMap inheritanceMap;    // 继承信息

    public SimpleSerializableDecider(InheritanceMap inheritanceMap) {
        this.inheritanceMap = inheritanceMap;
    }

    /**
     * 判断类是否可以序列化，并将判断结果添加到缓存
     *
     * @param handle 类
     * @return
     */
    @Override
    public Boolean apply(ClassReference.Handle handle) {
        Boolean cached = cache.get(handle);
        if (cached != null) {
            return cached;
        }

        Boolean result = applyNoCache(handle);

        cache.put(handle, result);
        return result;
    }

    /**
     * 判断类是否可以序列化
     *
     * @param handle 类
     * @return
     */
    private Boolean applyNoCache(ClassReference.Handle handle) {

        // 判断类是否在黑名单内
        if (isBlacklistedClass(handle)) {
            return false;
        }

        // 判断是否有直接或间接实现 java/io/Serializable 序列化接口
        if (inheritanceMap.isSubclassOf(handle, new ClassReference.Handle("java/io/Serializable"))) {
            return true;
        }

        return false;
    }

    /**
     * 判断类是否在黑名单内
     *
     * @param clazz 类
     * @return
     */
    private static boolean isBlacklistedClass(ClassReference.Handle clazz) {
        if (clazz.getName().startsWith("com/google/common/collect/")) {
            return true;
        }

        // Serialization of these classes has been disabled since clojure 1.9.0
        // https://github.com/clojure/clojure/commit/271674c9b484d798484d134a5ac40a6df15d3ac3
        if (clazz.getName().equals("clojure/core/proxy$clojure/lang/APersistentMap$ff19274a")
                || clazz.getName().equals("clojure/inspector/proxy$javax/swing/table/AbstractTableModel$ff19274a")) {
            return true;
        }

        return false;
    }
}
