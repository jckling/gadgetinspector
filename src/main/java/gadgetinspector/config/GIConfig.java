package gadgetinspector.config;

import gadgetinspector.ImplementationFinder;
import gadgetinspector.SerializableDecider;
import gadgetinspector.SourceDiscovery;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;

import java.util.Map;
import java.util.Set;

public interface GIConfig {

    // 配置名称
    String getName();

    // 序列化决策者
    SerializableDecider getSerializableDecider(Map<MethodReference.Handle, MethodReference> methodMap, InheritanceMap inheritanceMap);

    // 查找可序列化的重写方法
    ImplementationFinder getImplementationFinder(Map<MethodReference.Handle, MethodReference> methodMap,
                                                 Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap,
                                                 InheritanceMap inheritanceMap);

    // 查找污点源
    SourceDiscovery getSourceDiscovery();

}
