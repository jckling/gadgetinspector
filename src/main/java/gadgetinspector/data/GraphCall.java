package gadgetinspector.data;

public class GraphCall {
    private final MethodReference.Handle callerMethod;  // 调用者（方法）
    private final MethodReference.Handle targetMethod;  // 被调用者（方法）
    private final int callerArgIndex;   // 调用者（方法）的参数索引
    private final String callerArgPath; // 参数对象的哪个字段被传递
    private final int targetArgIndex;   // 被调用者（方法）的参数索引

    public GraphCall(MethodReference.Handle callerMethod, MethodReference.Handle targetMethod, int callerArgIndex, String callerArgPath, int targetArgIndex) {
        this.callerMethod = callerMethod;
        this.targetMethod = targetMethod;
        this.callerArgIndex = callerArgIndex;
        this.callerArgPath = callerArgPath;
        this.targetArgIndex = targetArgIndex;
    }

    public MethodReference.Handle getCallerMethod() {
        return callerMethod;
    }

    public MethodReference.Handle getTargetMethod() {
        return targetMethod;
    }

    public int getCallerArgIndex() {
        return callerArgIndex;
    }

    public String getCallerArgPath() {
        return callerArgPath;
    }

    public int getTargetArgIndex() {
        return targetArgIndex;
    }

    @Override
    public boolean equals(Object o) {   // 比较方法
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GraphCall graphCall = (GraphCall) o;

        if (callerArgIndex != graphCall.callerArgIndex) return false;
        if (targetArgIndex != graphCall.targetArgIndex) return false;
        if (callerMethod != null ? !callerMethod.equals(graphCall.callerMethod) : graphCall.callerMethod != null)
            return false;
        if (targetMethod != null ? !targetMethod.equals(graphCall.targetMethod) : graphCall.targetMethod != null)
            return false;
        return callerArgPath != null ? callerArgPath.equals(graphCall.callerArgPath) : graphCall.callerArgPath == null;
    }

    @Override
    public int hashCode() { // 存储到键值数据格式中调用的比较方法
        int result = callerMethod != null ? callerMethod.hashCode() : 0;
        result = 31 * result + (targetMethod != null ? targetMethod.hashCode() : 0);
        result = 31 * result + callerArgIndex;
        result = 31 * result + (callerArgPath != null ? callerArgPath.hashCode() : 0);
        result = 31 * result + targetArgIndex;
        return result;
    }

    /**
     * 数据工厂接口实现
     */
    public static class Factory implements DataFactory<GraphCall> {

        @Override
        public GraphCall parse(String[] fields) {
            return new GraphCall(
                    new MethodReference.Handle(new ClassReference.Handle(fields[0]), fields[1], fields[2]),
                    new MethodReference.Handle(new ClassReference.Handle(fields[3]), fields[4], fields[5]),
                    Integer.parseInt(fields[6]),
                    fields[7],
                    Integer.parseInt(fields[8]));
        }

        @Override
        public String[] serialize(GraphCall obj) {
            return new String[]{
                    obj.callerMethod.getClassReference().getName(), obj.callerMethod.getName(), obj.callerMethod.getDesc(),
                    obj.targetMethod.getClassReference().getName(), obj.targetMethod.getName(), obj.targetMethod.getDesc(),
                    Integer.toString(obj.callerArgIndex),
                    obj.callerArgPath,
                    Integer.toString(obj.targetArgIndex),
            };
        }
    }
}
