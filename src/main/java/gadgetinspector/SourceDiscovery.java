package gadgetinspector;

import gadgetinspector.data.*;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/* FIXME: This source discovery is limited to standard serializable objects; doesn't do proper source discovery for
 * non-standard Xstream cases. */
public abstract class SourceDiscovery { // 抽象类

    // 保存找到的污点源
    private final List<Source> discoveredSources = new ArrayList<>();

    /**
     * 添加污点源
     *
     * @param source 污点
     */
    protected final void addDiscoveredSource(Source source) {
        discoveredSources.add(source);
    }


    /**
     * 查找污点源
     *
     * @throws IOException
     */
    public void discover() throws IOException {
        // 加载类信息
        Map<ClassReference.Handle, ClassReference> classMap = DataLoader.loadClasses();
        // 加载函数信息
        Map<MethodReference.Handle, MethodReference> methodMap = DataLoader.loadMethods();
        // 加载继承信息
        InheritanceMap inheritanceMap = InheritanceMap.load();

        // 调用实现类的 discover 方法
        discover(classMap, methodMap, inheritanceMap);
    }

    /**
     * 抽象方法 -> 具体实现
     *
     * @param classMap       类信息
     * @param methodMap      方法信息
     * @param inheritanceMap 继承信息
     */
    public abstract void discover(Map<ClassReference.Handle, ClassReference> classMap,
                                  Map<MethodReference.Handle, MethodReference> methodMap,
                                  InheritanceMap inheritanceMap);

    /**
     * 使用工厂方法存储污点源信息
     *
     * @throws IOException
     */
    public void save() throws IOException {
        DataLoader.saveData(Paths.get("sources.dat"), new Source.Factory(), discoveredSources);
    }
}
