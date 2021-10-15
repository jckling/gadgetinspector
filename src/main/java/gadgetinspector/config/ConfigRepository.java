package gadgetinspector.config;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class ConfigRepository {
    // 配置列表
    private static final List<GIConfig> ALL_CONFIGS = Collections.unmodifiableList(Arrays.asList(
            new JavaDeserializationConfig(),        // Java 原生序列化
            new JacksonDeserializationConfig(),     // Jackson（Json）
            new XstreamDeserializationConfig()));   // XStream（XML）

    /**
     * 返回配置
     *
     * @param name 配置名称
     * @return
     */
    public static GIConfig getConfig(String name) {
        for (GIConfig config : ALL_CONFIGS) {
            if (config.getName().equals(name)) {
                return config;
            }
        }
        return null;
    }
}
