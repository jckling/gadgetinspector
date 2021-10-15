package gadgetinspector;

import gadgetinspector.config.GIConfig;
import gadgetinspector.config.JavaDeserializationConfig;
import gadgetinspector.data.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class GadgetChainDiscovery {

    private static final Logger LOGGER = LoggerFactory.getLogger(GadgetChainDiscovery.class);

    private final GIConfig config;

    public GadgetChainDiscovery(GIConfig config) {
        this.config = config;
    }

    /**
     * 搜索可能的利用链，保存到 gadget-chains.txt 中
     *
     * @throws Exception
     */
    public void discover() throws Exception {
        // 加载方法信息
        Map<MethodReference.Handle, MethodReference> methodMap = DataLoader.loadMethods();
        // 加载继承信息（inheritanceMap：子类->父类集合，subClassMap：父类->子类集合）
        InheritanceMap inheritanceMap = InheritanceMap.load();
        // 加载重写信息：方法->重写方法集合
        Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap = InheritanceDeriver.getAllMethodImplementations(
                inheritanceMap, methodMap);

        // 返回目标方法的可序列化重写方法（包括目标方法本身）
        final ImplementationFinder implementationFinder = config.getImplementationFinder(
                methodMap, methodImplMap, inheritanceMap);

        // 保存重写信息到 methodimpl.dat：（缩进）类名 方法名 描述符
        try (Writer writer = Files.newBufferedWriter(Paths.get("methodimpl.dat"))) {
            for (Map.Entry<MethodReference.Handle, Set<MethodReference.Handle>> entry : methodImplMap.entrySet()) {
                writer.write(entry.getKey().getClassReference().getName());
                writer.write("\t");
                writer.write(entry.getKey().getName());
                writer.write("\t");
                writer.write(entry.getKey().getDesc());
                writer.write("\n");
                for (MethodReference.Handle method : entry.getValue()) {
                    writer.write("\t");
                    writer.write(method.getClassReference().getName());
                    writer.write("\t");
                    writer.write(method.getName());
                    writer.write("\t");
                    writer.write(method.getDesc());
                    writer.write("\n");
                }
            }
        }

        // 加载调用关系信息
        Map<MethodReference.Handle, Set<GraphCall>> graphCallMap = new HashMap<>();
        for (GraphCall graphCall : DataLoader.loadData(Paths.get("callgraph.dat"), new GraphCall.Factory())) {
            MethodReference.Handle caller = graphCall.getCallerMethod();
            if (!graphCallMap.containsKey(caller)) {
                Set<GraphCall> graphCalls = new HashSet<>();
                graphCalls.add(graphCall);
                graphCallMap.put(caller, graphCalls);
            } else {
                graphCallMap.get(caller).add(graphCall);
            }
        }

        // 已经访问过的方法（节点）
        Set<GadgetChainLink> exploredMethods = new HashSet<>();
        // 待分析的链
        LinkedList<GadgetChain> methodsToExplore = new LinkedList<>();
        // 加载所有 sources，并将每个 source 分别作为链的第一个节点
        for (Source source : DataLoader.loadData(Paths.get("sources.dat"), new Source.Factory())) {
            // 创建节点
            GadgetChainLink srcLink = new GadgetChainLink(source.getSourceMethod(), source.getTaintedArgIndex());
            if (exploredMethods.contains(srcLink)) {
                continue;
            }
            // 创建仅有一个节点的链
            methodsToExplore.add(new GadgetChain(Arrays.asList(srcLink)));
            // 将方法标记为已访问
            exploredMethods.add(srcLink);
        }

        // 循环次数
        long iteration = 0;
        // 保存找到的利用链
        Set<GadgetChain> discoveredGadgets = new HashSet<>();
        // BFS 搜索 source 到 sink 的利用链
        while (methodsToExplore.size() > 0) {
            if ((iteration % 1000) == 0) {
                LOGGER.info("Iteration " + iteration + ", Search space: " + methodsToExplore.size());
            }
            iteration += 1;

            GadgetChain chain = methodsToExplore.pop(); // 取出一条链
            GadgetChainLink lastLink = chain.links.get(chain.links.size() - 1); // 取这条链最后一个节点（方法）

            // 获取当前方法与其被调方法的调用关系
            Set<GraphCall> methodCalls = graphCallMap.get(lastLink.method);
            if (methodCalls != null) {
                for (GraphCall graphCall : methodCalls) {
                    // 如果当前方法的污染参数与被调方法受方法参数影响的索引不一致则跳过（即第 index 个参数）
                    // 判断 source 时，索引指出能够被攻击者控制的参数
                    if (graphCall.getCallerArgIndex() != lastLink.taintedArgIndex) {
                        continue;
                    }

                    // 获取被调方法的可序列化重写信息
                    Set<MethodReference.Handle> allImpls = implementationFinder.getImplementations(graphCall.getTargetMethod());

                    // 遍历被调方法的重写方法
                    for (MethodReference.Handle methodImpl : allImpls) {
                        GadgetChainLink newLink = new GadgetChainLink(methodImpl, graphCall.getTargetArgIndex());
                        // 如果被调方法已经被访问过了，则跳过，减少开销
                        // 但是跳过会使其他链在经过此节点时断掉
                        // 而去掉这步可能会遇到环状问题，造成路径无限增加
                        if (exploredMethods.contains(newLink)) {
                            continue;
                        }

                        // 新节点（被调方法）与之前的链组成新链
                        GadgetChain newChain = new GadgetChain(chain, newLink);
                        // 判断被调方法是否为 sink 点，如果是则加入利用链集合
                        if (isSink(methodImpl, graphCall.getTargetArgIndex(), inheritanceMap)) {
                            discoveredGadgets.add(newChain);
                        } else {    // 否则将新链加入待分析的链集合，被调方法加入已访问的方法集合
                            methodsToExplore.add(newChain);
                            exploredMethods.add(newLink);
                        }
                    }
                }
            }
        }

        // 将搜索到的利用链保存到 gadget-chains.txt
        try (OutputStream outputStream = Files.newOutputStream(Paths.get("gadget-chains.txt"));
             Writer writer = new OutputStreamWriter(outputStream, StandardCharsets.UTF_8)) {
            for (GadgetChain chain : discoveredGadgets) {
                printGadgetChain(writer, chain);
            }
        }

        LOGGER.info("Found {} gadget chains.", discoveredGadgets.size());
    }

    /**
     * 将利用链写入文件：（缩进）类名 方法名 方法描述符 传递污点的参数索引
     *
     * @param writer 写入流
     * @param chain  利用链
     * @throws IOException
     */
    private static void printGadgetChain(Writer writer, GadgetChain chain) throws IOException {
        writer.write(String.format("%s.%s%s (%d)%n",    // 污点源
                chain.links.get(0).method.getClassReference().getName(),    // 类名
                chain.links.get(0).method.getName(),    // 方法名
                chain.links.get(0).method.getDesc(),    // 描述符
                chain.links.get(0).taintedArgIndex));   // 污点参数索引
        for (int i = 1; i < chain.links.size(); i++) {  // 利用链
            writer.write(String.format("  %s.%s%s (%d)%n",
                    chain.links.get(i).method.getClassReference().getName(),
                    chain.links.get(i).method.getName(),
                    chain.links.get(i).method.getDesc(),
                    chain.links.get(i).taintedArgIndex));
        }
        writer.write("\n");
    }

    // 利用链
    private static class GadgetChain {
        private final List<GadgetChainLink> links;

        private GadgetChain(List<GadgetChainLink> links) {
            this.links = links;
        }

        private GadgetChain(GadgetChain gadgetChain, GadgetChainLink link) {
            List<GadgetChainLink> links = new ArrayList<GadgetChainLink>(gadgetChain.links);
            links.add(link);
            this.links = links;
        }
    }

    // 利用链（节点）
    private static class GadgetChainLink {
        private final MethodReference.Handle method;
        private final int taintedArgIndex;

        private GadgetChainLink(MethodReference.Handle method, int taintedArgIndex) {
            this.method = method;
            this.taintedArgIndex = taintedArgIndex;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            GadgetChainLink that = (GadgetChainLink) o;

            if (taintedArgIndex != that.taintedArgIndex) return false;
            return method != null ? method.equals(that.method) : that.method == null;
        }

        @Override
        public int hashCode() {
            int result = method != null ? method.hashCode() : 0;
            result = 31 * result + taintedArgIndex;
            return result;
        }
    }

    /*
    private Set<GadgetChain> getSources(Map<Long, String> classNameMap, Map<Long, MethodReferenceOld> methodIdMap, Map<Long, Set<Long>> inheritanceMap) {
        Long serializableClassId = null;
        for (Map.Entry<Long, String> entry : classNameMap.entrySet()) {
            if (entry.getValue().equals("java/io/Serializable")) {
                serializableClassId = entry.getKey();
                break;
            }
        }
        if (serializableClassId == null) {
            throw new IllegalStateException("No class ID found for java.io.Serializable");
        }

        Set<GadgetChain> sources = new HashSet<>();
        for (Map.Entry<Long, MethodReferenceOld> entry : methodIdMap.entrySet()) {
            MethodReferenceOld method = entry.getValue();
            if (inheritanceMap.get(method.getClassId()).contains(serializableClassId)
                    && method.getName().equals("readObject")
                    && method.getDesc().equals("(Ljava/io/ObjectInputStream;)V")) {
                sources.add(new GadgetChain(Arrays.asList(new GadgetChainLink(entry.getKey(), 0))));
            }
        }

        return sources;
    }
    */

    /**
     * 预定义的 sink 点
     * Represents a collection of methods in the JDK that we consider to be "interesting". If a gadget chain can
     * successfully exercise one of these, it could represent anything as mundade as causing the target to make a DNS
     * query to full blown RCE.
     *
     * @param method         方法
     * @param argIndex       参数索引
     * @param inheritanceMap 继承信息
     * @return
     */
    // TODO: Parameterize this as a configuration option
    private boolean isSink(MethodReference.Handle method, int argIndex, InheritanceMap inheritanceMap) {
        if (method.getClassReference().getName().equals("java/io/FileInputStream")
                && method.getName().equals("<init>")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/io/FileOutputStream")
                && method.getName().equals("<init>")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/nio/file/Files")
                && (method.getName().equals("newInputStream")
                || method.getName().equals("newOutputStream")
                || method.getName().equals("newBufferedReader")
                || method.getName().equals("newBufferedWriter"))) {
            return true;
        }

        if (method.getClassReference().getName().equals("java/lang/Runtime")
                && method.getName().equals("exec")) {
            return true;
        }
        /*
        if (method.getClassReference().getName().equals("java/lang/Class")
                && method.getName().equals("forName")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/lang/Class")
                && method.getName().equals("getMethod")) {
            return true;
        }
        */
        // If we can invoke an arbitrary method, that's probably interesting (though this doesn't assert that we
        // can control its arguments). Conversely, if we can control the arguments to an invocation but not what
        // method is being invoked, we don't mark that as interesting.
        if (method.getClassReference().getName().equals("java/lang/reflect/Method")
                && method.getName().equals("invoke") && argIndex == 0) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/net/URLClassLoader")
                && method.getName().equals("newInstance")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/lang/System")
                && method.getName().equals("exit")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/lang/Shutdown")
                && method.getName().equals("exit")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/lang/Runtime")
                && method.getName().equals("exit")) {
            return true;
        }

        if (method.getClassReference().getName().equals("java/nio/file/Files")
                && method.getName().equals("newOutputStream")) {
            return true;
        }

        if (method.getClassReference().getName().equals("java/lang/ProcessBuilder")
                && method.getName().equals("<init>") && argIndex > 0) {
            return true;
        }

        if (inheritanceMap.isSubclassOf(method.getClassReference(), new ClassReference.Handle("java/lang/ClassLoader"))
                && method.getName().equals("<init>")) {
            return true;
        }

        if (method.getClassReference().getName().equals("java/net/URL") && method.getName().equals("openStream")) {
            return true;
        }

        // Some groovy-specific sinks
        if (method.getClassReference().getName().equals("org/codehaus/groovy/runtime/InvokerHelper")
                && method.getName().equals("invokeMethod") && argIndex == 1) {
            return true;
        }

        if (inheritanceMap.isSubclassOf(method.getClassReference(), new ClassReference.Handle("groovy/lang/MetaClass"))
                && Arrays.asList("invokeMethod", "invokeConstructor", "invokeStaticMethod").contains(method.getName())) {
            return true;
        }

        // This jython-specific sink effectively results in RCE
        if (method.getClassReference().getName().equals("org/python/core/PyCode") && method.getName().equals("call")) {
            return true;
        }

        return false;
    }

    public static void main(String[] args) throws Exception {
        GadgetChainDiscovery gadgetChainDiscovery = new GadgetChainDiscovery(new JavaDeserializationConfig());
        gadgetChainDiscovery.discover();
    }
}
