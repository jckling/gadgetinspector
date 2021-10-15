package gadgetinspector;

import com.google.common.reflect.ClassPath;

import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Collection;

public class ClassResourceEnumerator {
    private final ClassLoader classLoader;

    public ClassResourceEnumerator(ClassLoader classLoader) throws IOException {
        this.classLoader = classLoader;
    }

    /**
     * 返回 java 运行时的类和指定的 java 包中的类
     *
     * @return
     * @throws IOException
     */
    public Collection<ClassResource> getAllClasses() throws IOException {
        // 先加载运行时类（bootstrap classes）
        Collection<ClassResource> result = new ArrayList<>(getRuntimeClasses());
        // 使用 ClassLoader 加载用户指定的 java 包
        for (ClassPath.ClassInfo classInfo : ClassPath.from(classLoader).getAllClasses()) {
            result.add(new ClassLoaderClassResource(classLoader, classInfo.getResourceName()));
        }
        return result;
    }

    /**
     * 返回运行时的类
     *
     * @return
     * @throws IOException
     */
    private Collection<ClassResource> getRuntimeClasses() throws IOException {
        // Java8 及以前的运行时类可以通过读取 rt.jar 文件获取
        // A hacky way to get the current JRE's rt.jar. Depending on the class loader, rt.jar may be in the
        // bootstrap classloader so all the JDK classes will be excluded from classpath scanning with this!
        // However, this only works up to Java 8, since after that Java uses some crazy module magic.
        URL stringClassUrl = Object.class.getResource("String.class");
        URLConnection connection = stringClassUrl.openConnection();
        Collection<ClassResource> result = new ArrayList<>();
        if (connection instanceof JarURLConnection) {
            URL runtimeUrl = ((JarURLConnection) connection).getJarFileURL();
            URLClassLoader classLoader = new URLClassLoader(new URL[]{runtimeUrl});

            for (ClassPath.ClassInfo classInfo : ClassPath.from(classLoader).getAllClasses()) {
                result.add(new ClassLoaderClassResource(classLoader, classInfo.getResourceName()));
            }
            return result;
        }

        // Java9 及以后的运行时类通过 JRT 文件系统读取路径下的类文件
        // https://stackoverflow.com/questions/1240387/where-are-the-java-system-packages-stored/53897006#53897006
        // Try finding all the JDK classes using the Java9+ modules method:
        try {
            FileSystem fs = FileSystems.getFileSystem(URI.create("jrt:/"));
            Files.walk(fs.getPath("/")).forEach(p -> {
                if (p.toString().toLowerCase().endsWith(".class")) {
                    result.add(new PathClassResource(p));
                }
            });
        } catch (ProviderNotFoundException e) {
            // Do nothing; this is expected on versions below Java9
        }

        return result;
    }

    // 类资源接口
    public static interface ClassResource {
        public InputStream getInputStream() throws IOException; // 读取文件

        public String getName();    // 文件名
    }

    // 直接从路径读取类文件
    private static class PathClassResource implements ClassResource {
        private final Path path;

        private PathClassResource(Path path) {
            this.path = path;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            return Files.newInputStream(path);
        }

        @Override
        public String getName() {
            return path.toString();
        }
    }

    // 使用 ClassLoader 读取类文件
    private static class ClassLoaderClassResource implements ClassResource {
        private final ClassLoader classLoader;
        private final String resourceName;

        private ClassLoaderClassResource(ClassLoader classLoader, String resourceName) {
            this.classLoader = classLoader;
            this.resourceName = resourceName;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            return classLoader.getResourceAsStream(resourceName);
        }

        @Override
        public String getName() {
            return resourceName;
        }
    }
}
