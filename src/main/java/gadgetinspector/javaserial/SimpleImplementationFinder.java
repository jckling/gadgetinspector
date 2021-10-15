package gadgetinspector.javaserial;

import gadgetinspector.ImplementationFinder;
import gadgetinspector.SerializableDecider;
import gadgetinspector.data.MethodReference;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class SimpleImplementationFinder implements ImplementationFinder {

    private final SerializableDecider serializableDecider;  // 序列化决策者
    private final Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap;   // 重写方法

    public SimpleImplementationFinder(SerializableDecider serializableDecider, Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap) {
        this.serializableDecider = serializableDecider;
        this.methodImplMap = methodImplMap;
    }

    @Override
    public Set<MethodReference.Handle> getImplementations(MethodReference.Handle target) {
        // 存储可序列化的重写方法
        Set<MethodReference.Handle> allImpls = new HashSet<>();

        // Assume that the target method is always available, even if not serializable; the target may just be a local
        // instance rather than something an attacker can control.
        allImpls.add(target);   // 默认认为目标方法可序列化

        // 遍历重写方法
        Set<MethodReference.Handle> subClassImpls = methodImplMap.get(target);
        if (subClassImpls != null) {
            for (MethodReference.Handle subClassImpl : subClassImpls) {
                // 判断是否可序列化
                if (Boolean.TRUE.equals(serializableDecider.apply(subClassImpl.getClassReference()))) {
                    allImpls.add(subClassImpl); // 添加到 allImpls
                }
            }
        }

        return allImpls;
    }
}
