package gadgetinspector;

import gadgetinspector.data.MethodReference;

import java.util.Set;

public interface ImplementationFinder {
    Set<MethodReference.Handle> getImplementations(MethodReference.Handle target); // 查找可序列化的重写方法
}
