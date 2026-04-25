package evmpwst.network;
public final class FailureHandler {
    private FailureHandler() {}
    public static void handleSecurityFailure(String errorCode, Throwable cause) {
        throw new SecurityException("EVMPwST security failure [" + errorCode + "]", sanitizeCause(cause));
    }
    public static void handleSecurityFailure(String errorCode) {
        throw new SecurityException("EVMPwST security failure [" + errorCode + "]");
    }
    public static void handleOperationalFailure(String message, Throwable cause) {
        throw new RuntimeException("EVMPwST operational failure: " + message, cause);
    }
    public static void require(boolean condition, String errorCode) {
        if (!condition) {
            handleSecurityFailure(errorCode);
        }
    }
    private static Throwable sanitizeCause(Throwable t) {
        if (t == null) return null;
        if (t.getClass().getName().contains("AEADBadTagException")) {
            return new SecurityException("Authentication tag verification failed");
        }
        return new RuntimeException(t.getClass().getSimpleName());
    }
}
