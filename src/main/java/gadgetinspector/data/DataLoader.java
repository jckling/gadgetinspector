package gadgetinspector.data;

import com.google.common.io.Files;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class DataLoader {

    /**
     * 根据数据工厂接口解析数据到对象
     *
     * @param filePath 文件路径
     * @param factory  工厂方法
     * @param <T>      类型
     * @return
     * @throws IOException
     */
    public static <T> List<T> loadData(Path filePath, DataFactory<T> factory) throws IOException {
        final List<String> lines = Files.readLines(filePath.toFile(), StandardCharsets.UTF_8);
        final List<T> values = new ArrayList<T>(lines.size());
        for (String line : lines) {
            values.add(factory.parse(line.split("\t", -1)));
        }
        return values;
    }

    /**
     * 根据数据工厂接口将数据写入文件
     *
     * @param filePath 文件路径
     * @param factory  工厂方法
     * @param values   待写入的数据
     * @param <T>      类型
     * @throws IOException
     */
    public static <T> void saveData(Path filePath, DataFactory<T> factory, Collection<T> values) throws IOException {
        try (BufferedWriter writer = Files.newWriter(filePath.toFile(), StandardCharsets.UTF_8)) {
            for (T value : values) {
                final String[] fields = factory.serialize(value);
                if (fields == null) {
                    continue;
                }

                StringBuilder sb = new StringBuilder();
                for (String field : fields) {
                    if (field == null) {
                        sb.append("\t");
                    } else {
                        sb.append("\t").append(field);
                    }
                }
                writer.write(sb.substring(1));
                writer.write("\n");
            }
        }
    }

    /**
     * 从 classes.dat 加载类信息
     *
     * @return
     */
    public static Map<ClassReference.Handle, ClassReference> loadClasses() {
        try {
            Map<ClassReference.Handle, ClassReference> classMap = new HashMap<>();
            for (ClassReference classReference : loadData(Paths.get("classes.dat"), new ClassReference.Factory())) {
                classMap.put(classReference.getHandle(), classReference);
            }
            return classMap;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 从 methods.dat 加载方法信息
     *
     * @return
     */
    public static Map<MethodReference.Handle, MethodReference> loadMethods() {
        try {
            Map<MethodReference.Handle, MethodReference> methodMap = new HashMap<>();
            for (MethodReference methodReference : loadData(Paths.get("methods.dat"), new MethodReference.Factory())) {
                methodMap.put(methodReference.getHandle(), methodReference);
            }
            return methodMap;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
