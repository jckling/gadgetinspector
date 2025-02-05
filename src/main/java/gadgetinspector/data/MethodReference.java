package gadgetinspector.data;

public class MethodReference {
    private final ClassReference.Handle classReference; // 所属类
    private final String name;                          // 方法名
    private final String desc;                          // 描述符
    private final boolean isStatic;                     // 是否为静态方法

    public MethodReference(ClassReference.Handle classReference, String name, String desc, boolean isStatic) {
        this.classReference = classReference;
        this.name = name;
        this.desc = desc;
        this.isStatic = isStatic;
    }

    public ClassReference.Handle getClassReference() {
        return classReference;
    }

    public String getName() {
        return name;
    }

    public String getDesc() {
        return desc;
    }

    public boolean isStatic() {
        return isStatic;
    }

    public Handle getHandle() {
        return new Handle(classReference, name, desc);
    }

    public static class Handle {
        private final ClassReference.Handle classReference; // 所属类
        private final String name;                          // 方法名
        private final String desc;                          // 描述符

        public Handle(ClassReference.Handle classReference, String name, String desc) {
            this.classReference = classReference;
            this.name = name;
            this.desc = desc;
        }

        public ClassReference.Handle getClassReference() {
            return classReference;
        }

        public String getName() {
            return name;
        }

        public String getDesc() {
            return desc;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Handle handle = (Handle) o;

            if (classReference != null ? !classReference.equals(handle.classReference) : handle.classReference != null)
                return false;
            if (name != null ? !name.equals(handle.name) : handle.name != null) return false;
            return desc != null ? desc.equals(handle.desc) : handle.desc == null;
        }

        @Override
        public int hashCode() {
            int result = classReference != null ? classReference.hashCode() : 0;
            result = 31 * result + (name != null ? name.hashCode() : 0);
            result = 31 * result + (desc != null ? desc.hashCode() : 0);
            return result;
        }
    }

    /**
     * 数据工厂接口实现
     */
    public static class Factory implements DataFactory<MethodReference> {

        @Override
        public MethodReference parse(String[] fields) {
            return new MethodReference(
                    new ClassReference.Handle(fields[0]),
                    fields[1],
                    fields[2],
                    Boolean.parseBoolean(fields[3]));
        }

        @Override
        public String[] serialize(MethodReference obj) {
            return new String[]{
                    obj.classReference.getName(),
                    obj.name,
                    obj.desc,
                    Boolean.toString(obj.isStatic),
            };
        }
    }
}
