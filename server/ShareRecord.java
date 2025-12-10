import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class ShareRecord {
    public final String id;
    public final Set<String> authorized;
    public final Map<String, String> permissions;
    
    public ShareRecord(String ownerId) {
        this.id = ownerId;
        this.authorized = ConcurrentHashMap.newKeySet();
        this.permissions = new ConcurrentHashMap<>();
    }
}
