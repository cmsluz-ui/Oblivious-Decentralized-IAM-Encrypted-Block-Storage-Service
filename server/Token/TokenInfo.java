package Token;

public class TokenInfo {
    public boolean valid;
    public String reason;
    public String anonId;
    public long issuedAt;

    public TokenInfo() {
        valid = false;
        reason = null;
        anonId = null;
        issuedAt = 0;
    }
}
