package com.ohos.migrator.test.java;

public class TestBoolean {
    public static void func() {
        Boolean v1 = Boolean.TRUE;
        Boolean v2 = Boolean.FALSE;
        Class<Boolean> v3 = Boolean.TYPE;
        boolean v4 = Boolean.TRUE.booleanValue();
        int v5 = Boolean.compare(Boolean.TRUE, Boolean.FALSE);
        int v6 = Boolean.TRUE.compareTo(Boolean.TRUE);
        boolean v7 = Boolean.TRUE.equals(Boolean.TRUE);
        boolean v8 = Boolean.getBoolean("false");
        int v9 = Boolean.hashCode(false);
        int v10 = Boolean.TRUE.hashCode();
        boolean v11 = Boolean.logicalAnd(false, true);
        boolean v12 = Boolean.logicalOr(false, true);
        boolean v13 = Boolean.logicalXor(false, true);
        boolean v14 = Boolean.parseBoolean("true");
        String v15 = Boolean.toString(true);
        String v16 = Boolean.TRUE.toString();
        boolean v17 = Boolean.valueOf(true);
        boolean v18 = Boolean.valueOf("");
    }
}
