package gadgetinspector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

public class Util {

    private static final Logger LOGGER = LoggerFactory.getLogger(Util.class);

    /**
     * 根据 war 包路径列表，构造并返回 URLClassLoader
     *
     * @param warPath 包路径列表
     * @return
     * @throws IOException
     */
    public static ClassLoader getWarClassLoader(Path warPath) throws IOException {
        // 创建临时文件夹
        final Path tmpDir = Files.createTempDirectory("exploded-war");
        // Delete the temp directory at shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                deleteDirectory(tmpDir);
            } catch (IOException e) {
                LOGGER.error("Error cleaning up temp directory " + tmpDir.toString(), e);
            }
        }));

        // 复制到临时文件夹
        // Extract to war to the temp directory
        try (JarInputStream jarInputStream = new JarInputStream(Files.newInputStream(warPath))) {
            JarEntry jarEntry;
            while ((jarEntry = jarInputStream.getNextJarEntry()) != null) {
                Path fullPath = tmpDir.resolve(jarEntry.getName());
                if (!jarEntry.isDirectory()) {
                    Path dirName = fullPath.getParent();
                    if (dirName == null) {
                        throw new IllegalStateException("Parent of item is outside temp directory.");
                    }
                    if (!Files.exists(dirName)) {
                        Files.createDirectories(dirName);
                    }
                    try (OutputStream outputStream = Files.newOutputStream(fullPath)) {
                        copy(jarInputStream, outputStream);
                    }
                }
            }
        }

        // 存储包路径
        final List<URL> classPathUrls = new ArrayList<>();
        classPathUrls.add(tmpDir.resolve("WEB-INF/classes").toUri().toURL());
        Files.list(tmpDir.resolve("WEB-INF/lib")).forEach(p -> {
            try {
                classPathUrls.add(p.toUri().toURL());
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            }
        });
        URLClassLoader classLoader = new URLClassLoader(classPathUrls.toArray(new URL[classPathUrls.size()]));
        return classLoader;
    }

    /**
     * 根据 jar 包路径列表，构造并返回 URLClassLoader
     *
     * @param jarPaths 包路径列表
     * @return
     * @throws IOException
     */
    public static ClassLoader getJarClassLoader(Path... jarPaths) throws IOException {
        // 存储包路径
        final List<URL> classPathUrls = new ArrayList<>(jarPaths.length);
        // 遍历包路径列表
        for (Path jarPath : jarPaths) {
            if (!Files.exists(jarPath) || Files.isDirectory(jarPath)) { // 查找文件
                throw new IllegalArgumentException("Path \"" + jarPath + "\" is not a path to a file.");
            }
            classPathUrls.add(jarPath.toUri().toURL()); //
        }
        URLClassLoader classLoader = new URLClassLoader(classPathUrls.toArray(new URL[classPathUrls.size()]));
        return classLoader;
    }

    /**
     * Recursively delete the directory root and all its contents
     *
     * @param root Root directory to be deleted
     * @throws IOException
     */
    public static void deleteDirectory(Path root) throws IOException {
        Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                Files.delete(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    /**
     * Copy inputStream to outputStream. Neither stream is closed by this method.
     *
     * @param inputStream
     * @param outputStream
     * @throws IOException
     */
    public static void copy(InputStream inputStream, OutputStream outputStream) throws IOException {
        final byte[] buffer = new byte[4096];
        int n;
        while ((n = inputStream.read(buffer)) > 0) {
            outputStream.write(buffer, 0, n);
        }
    }
}
