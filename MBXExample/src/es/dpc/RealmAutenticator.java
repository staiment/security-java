package es.dpc;

import java.util.Collections;

import javax.management.remote.JMXAuthenticator;
import javax.management.remote.JMXPrincipal;
import javax.security.auth.Subject;

public class RealmAutenticator  implements JMXAuthenticator {

	        public Subject authenticate(Object credentials) {

	            // Verify that credentials is of type String[].
	            //
	            if (!(credentials instanceof String[])) {
	                // Special case for null so we get a more informative message
	                if (credentials == null) {
	                    throw new SecurityException("Credentials required");
	                }
	                throw new SecurityException("Credentials should be String[]");
	            }

	            // Verify that the array contains three elements (username/password/realm).
	            //
	            final String[] aCredentials = (String[]) credentials;
//	            if (aCredentials.length != 3) {
//	                throw new SecurityException("Credentials should have 3 elements");
//	            }

	            // Perform authentication
	            //
	            String username = (String) aCredentials[0];
	            String password = (String) aCredentials[1];
//	            String realm = (String) aCredentials[2];

	            boolean authentication=username.equals("a") && password.equals("b");
	            
	            if (authentication) {
	                return new Subject(true,
	                                   Collections.singleton(new JMXPrincipal(username)),
	                                   Collections.EMPTY_SET,
	                                   Collections.EMPTY_SET);
	            } else {
	                throw new SecurityException("Invalid credentials");
	            }
	        }
}