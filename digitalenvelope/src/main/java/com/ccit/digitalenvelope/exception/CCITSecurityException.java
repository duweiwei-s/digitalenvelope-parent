package com.ccit.digitalenvelope.exception;


/**
 * @author liuna
 * @version 1.0
 */
public class CCITSecurityException extends Exception
{

	public CCITSecurityException (String msg)
	{
		super (msg);
	}
	public CCITSecurityException(String message, Throwable cause) {
		super(message, cause);
	}
}
