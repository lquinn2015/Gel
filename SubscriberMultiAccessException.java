package gel;

public class SubscriberMultiAccessException extends Exception {

	
	public String reason;
	
	public SubscriberMultiAccessException(String reason) {
		super();
		this.reason = reason;
	}
	
}
