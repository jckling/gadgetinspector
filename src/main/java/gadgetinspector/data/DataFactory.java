package gadgetinspector.data;

// 数据工厂接口
public interface DataFactory<T> {
    T parse(String[] fields);

    String[] serialize(T obj);
}
