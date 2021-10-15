package gadgetinspector;

import gadgetinspector.config.ConfigRepository;
import gadgetinspector.config.GIConfig;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.PatternLayout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Main entry point for running an end-to-end analysis. Deletes all data files before starting and writes discovered
 * gadget chains to gadget-chains.txt.
 */
public class GadgetInspector {
    private static final Logger LOGGER = LoggerFactory.getLogger(GadgetInspector.class);

    // 打印使用帮助
    private static void printUsage() {
        System.out.println("Usage:\n  Pass either a single argument which will be interpreted as a WAR, or pass " +
                "any number of arguments which will be intepretted as a list of JARs forming a classpath.");

    }

    // 入口
    public static void main(String[] args) throws Exception {
        // 判断参数是否为空，至少要指定一个 java 包
        if (args.length == 0) {
            printUsage();   // 打印使用帮助
            System.exit(1);
        }

        // 配置 log4j 用于输出日志
        configureLogging();

        // 是否保留所有的 .dat 文件
        boolean resume = false;
        // 挖掘类型，默认为 java 原生序列化
        GIConfig config = ConfigRepository.getConfig("jserial");    // 实现 SerializableDecider、ImplementationFinder、SourceDiscovery

        // 解析参数
        int argIndex = 0;
        while (argIndex < args.length) {
            String arg = args[argIndex];
            if (!arg.startsWith("--")) {
                break;
            }
            if (arg.equals("--resume")) {
                // 保留 .dat 文件
                resume = true;
            } else if (arg.equals("--config")) {
                // 指定挖掘类型
                config = ConfigRepository.getConfig(args[++argIndex]);
                if (config == null) {
                    throw new IllegalArgumentException("Invalid config name: " + args[argIndex]);
                }
            } else {
                throw new IllegalArgumentException("Unexpected argument: " + arg);
            }

            argIndex += 1;
        }

        // 实际上是 URLClassLoader
        final ClassLoader classLoader;
        // 对指定文件根据 war、spring-boot jar、普通 jar 包的方式载入对于字节码文件，并返回 URLClassLoader
        if (args.length == argIndex + 1 && args[argIndex].toLowerCase().endsWith(".war")) {
            // 构造 war 文件路径
            Path path = Paths.get(args[argIndex]);
            LOGGER.info("Using WAR classpath: " + path);
            // 实现为 URLClassLoader，加载 war 包下的 WEB-INF/lib 和 WEB-INF/classes
            classLoader = Util.getWarClassLoader(path);
        } else {
            // 构造 jar 文件路径，可配置多个
            final Path[] jarPaths = new Path[args.length - argIndex];
            for (int i = 0; i < args.length - argIndex; i++) {
                Path path = Paths.get(args[argIndex + i]).toAbsolutePath();
                if (!Files.exists(path)) {
                    throw new IllegalArgumentException("Invalid jar path: " + path);
                }
                jarPaths[i] = path;
            }
            LOGGER.info("Using classpath: " + Arrays.toString(jarPaths));
            // 实现为 URLClassLoader，加载所有指定的 jar
            classLoader = Util.getJarClassLoader(jarPaths);
        }

        // 类枚举加载器，具有两个方法
        // getRuntimeClasses 获取 rt.jar 的所有 class
        // getAllClasses 获取 rt.jar 以及 classLoader 加载的 class
        final ClassResourceEnumerator classResourceEnumerator = new ClassResourceEnumerator(classLoader);

        // 删除所有的 .dat 文件
        if (!resume) {
            // Delete all existing dat files
            LOGGER.info("Deleting stale data...");
            // 挖掘到的利用链存储在 gadget-chains.txt 中，不删除
            for (String datFile : Arrays.asList("classes.dat", "methods.dat", "inheritanceMap.dat",
                    "passthrough.dat", "callgraph.dat", "sources.dat", "methodimpl.dat")) {
                final Path path = Paths.get(datFile);
                if (Files.exists(path)) {
                    Files.delete(path);
                }
            }
        }

        // Perform the various discovery steps
        if (!Files.exists(Paths.get("classes.dat")) || !Files.exists(Paths.get("methods.dat"))
                || !Files.exists(Paths.get("inheritanceMap.dat"))) {
            LOGGER.info("Running method discovery...");
            MethodDiscovery methodDiscovery = new MethodDiscovery();
            methodDiscovery.discover(classResourceEnumerator);
            methodDiscovery.save(); // 保存类信息、方法信息、继承信息
        }

        if (!Files.exists(Paths.get("passthrough.dat"))) {
            LOGGER.info("Analyzing methods for passthrough dataflow...");
            PassthroughDiscovery passthroughDiscovery = new PassthroughDiscovery();
            passthroughDiscovery.discover(classResourceEnumerator, config);
            passthroughDiscovery.save();    // 保存数据流信息（方法参数和返回值的关系信息）
        }

        if (!Files.exists(Paths.get("callgraph.dat"))) {
            LOGGER.info("Analyzing methods in order to build a call graph...");
            CallGraphDiscovery callGraphDiscovery = new CallGraphDiscovery();
            callGraphDiscovery.discover(classResourceEnumerator, config);
            callGraphDiscovery.save();  // 保存调用关系信息（调用者方法与被调方法之间的参数传递）
        }

        if (!Files.exists(Paths.get("sources.dat"))) {
            LOGGER.info("Discovering gadget chain source methods...");
            SourceDiscovery sourceDiscovery = config.getSourceDiscovery();
            sourceDiscovery.discover();
            sourceDiscovery.save(); // 保存污点源信息
        }

        {
            LOGGER.info("Searching call graph for gadget chains...");
            GadgetChainDiscovery gadgetChainDiscovery = new GadgetChainDiscovery(config);
            gadgetChainDiscovery.discover();    // 保存重写信息、利用链信息
        }

        LOGGER.info("Analysis complete!");
    }

    // 配置 log4j 输出到控制台
    private static void configureLogging() {
        ConsoleAppender console = new ConsoleAppender();
        String PATTERN = "%d %c [%p] %m%n";
        console.setLayout(new PatternLayout(PATTERN));
        console.setThreshold(Level.DEBUG);
        console.activateOptions();
        org.apache.log4j.Logger.getRootLogger().addAppender(console);
    }
}
