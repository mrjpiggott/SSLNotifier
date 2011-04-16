if ("undefined" == typeof(SSLNotifier)) {
  var SSLNotifier = {
    init : function() {
		var file = Components.classes["@mozilla.org/file/directory_service;1"]
			 .getService(Components.interfaces.nsIProperties)
			 .get("ProfD", Components.interfaces.nsIFile);
		file.append("sslnotifier.sqlite");

		var storageService = Components.classes["@mozilla.org/storage/service;1"]
				.getService(Components.interfaces.mozIStorageService); 
		this.mDBConn = storageService.openDatabase(file);
		while(!this.mDBConn.connectionReady){}
		if (!this.mDBConn.tableExists("certs"))	{
			this.mDBConn.executeSimpleSQL("CREATE TABLE certs (host TEXT, cn TEXT, org TEXT, issuer TEXT, sha TEXT, PRIMARY KEY(host ASC));");
		}
	}
  };

  (function() {
    this.init();
  }).apply(SSLNotifier);
};

SSLNotifier.exit = function() {
	this.mDBConn.asyncClose();
};




/***********************
 * Database Code
 ***********************/
SSLNotifier.handleCert = function(cert, host) {
	var statement = SSLNotifier.mDBConn.createStatement("SELECT * FROM certs WHERE host = :host");
	statement.params.host = host;
	statement.executeAsync({
		  handleResult: function(aResultSet) {
				var row = aResultSet.getNextRow();
				if (row) {
					this.rowCount++;
					var cert = SSLNotifier.rowToCert(row);
					// Is it different, is sha1 sufficient?
					if (this.newCert.sha1Fingerprint != cert.sha1Fingerprint) {
						SSLNotifier.certChanged(cert, this.newCert, this.host, this.location);
					}
				}
		  },
		  handleError: function(aError) {
		  // TODO log this?
		  },
		  handleCompletion: function(aReason) {
			if (aReason == Components.interfaces.mozIStorageStatementCallback.REASON_FINISHED && this.rowCount == 0) {
				SSLNotifier.newCert(this.newCert, this.host, this.location);
			}
		  },
		  host: host,
		  location: location,
		  newCert: cert,
		  rowCount: 0
		});
};

// Add a new certificate
SSLNotifier.store = function(cert, host) {
	var statement = this.mDBConn.createStatement("INSERT INTO certs (host, cn, org, issuer, sha) VALUES (:host, :cn, :org, :issuer, :sha)");
	statement.params.cn = cert.commonName;
	statement.params.org = cert.organization;
	statement.params.issuer = cert.issuerOrganization;
	statement.params.sha = cert.sha1Fingerprint;
	statement.params.host = host;
	statement.executeAsync();
};

// Replace an existing certificate
SSLNotifier.update = function(cert, host) {
	var statement = this.mDBConn.createStatement("UPDATE certs SET cn = :cn, org = :org, issuer = :issuer, sha = :sha WHERE host = :host");
	statement.params.cn = cert.commonName;
	statement.params.org = cert.organization;
	statement.params.issuer = cert.issuerOrganization;
	statement.params.sha = cert.sha1Fingerprint;
	statement.params.host = host;
	statement.executeAsync();
};

// Convert a database row to a "Certificate"
SSLNotifier.rowToCert = function(row) {
	return SSLNotifier.toCert(row.getResultByName("cn"), row.getResultByName("org"), row.getResultByName("issuer"), row.getResultByName("sha"));
};




/***********************
 * Browser Code
 ***********************/
SSLNotifier.onPageLoad = function(aEvent) {	
	var location = "" + aEvent.originalTarget.location;
	if (location.indexOf('https://',0) != 0) {
		// Avoid some weird page notifications like javascript:''
		return;
	}
  	var ui = gBrowser.securityUI;
    var sp = ui.QueryInterface(Components.interfaces.nsISSLStatusProvider);
	var status = sp.SSLStatus;
	if (status != null) {
		status = status.QueryInterface(Components.interfaces.nsISSLStatus);
		// It seems to be necessary to copy the certificate as it disappears on asynchronous calls.
		SSLNotifier.handleCert(SSLNotifier.toCert(status.serverCert.commonName, status.serverCert.organization, status.serverCert.issuerOrganization, status.serverCert.sha1Fingerprint), 
				SSLNotifier.getHost(location));
	}
};

SSLNotifier.getBrowser = function(url) {
  var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"]
                     .getService(Components.interfaces.nsIWindowMediator);
  var browserEnumerator = wm.getEnumerator("navigator:browser");

  // Check each browser instance for our URL
  var found = false;
  while (!found && browserEnumerator.hasMoreElements()) {
    var browserWin = browserEnumerator.getNext();
    var tabbrowser = browserWin.gBrowser;

    // Check each tab of this browser instance
    var numTabs = tabbrowser.browsers.length;
    for (var index = 0; index < numTabs; index++) {
      var currentBrowser = tabbrowser.getBrowserAtIndex(index);
      if (url == currentBrowser.currentURI.spec) {
        // The URL is already opened. Select this tab.
        return tabbrowser.tabContainer.childNodes[index];
      }
    }
  }
};




/***********************
 * Notification
 ***********************/
SSLNotifier.newCert = function(cert, host, location) {
	var nb = gBrowser.getNotificationBox(SSLNotifier.getBrowser(location));
	var msg = "SSL Notification: Store certificate for host " + host;
	nb.appendNotification(msg, "ca.piggott.sslnotifier", null, nb.PRIORITY_INFO_HIGH, [SSLNotifier.storeBtn(cert, host)]);
};

SSLNotifier.certChanged = function(oldCert, cert, host, location) {
	var nb = gBrowser.getNotificationBox(SSLNotifier.getBrowser(location));
	var msg = "CERTIFICATE CHANGED: formerly issued by " + oldCert.issuerOrganization + " to " + oldCert.organization ;
	nb.appendNotification(msg, "ca.piggott.sslnotifier", null, nb.PRIORITY_CRITICAL_HIGH, [SSLNotifier.updateBtn(cert, host)]);
};

SSLNotifier.storeBtn = function(cert, host) {
	var button = new Object();
	button.label = "Store";
	button.callback = function (event) {
		SSLNotifier.store(cert, host);
		};
	button.cert = cert;
	button.host = host;
	button.accessKey = null;
	return button;
};

SSLNotifier.updateBtn = function(cert, host) {
	var button = new Object();
	button.label = "Update";
	button.callback = function (event) {
		SSLNotifier.update(cert, host);
		};
	button.cert = cert;
	button.host = host;
	button.accessKey = null;
	return button;
};

/***********************
 * Helper Code
 ***********************/

// Extract host from URL, assumes https
SSLNotifier.getHost = function(location) {
	return location.substring(8, location.indexOf('/',8));
};

// Create a "Certificate" object, the xpcom one seems to disappear
SSLNotifier.toCert = function(cn, org, issuer, sha) {
	var cert = new Object();
	cert.commonName = ""+cn;
	cert.organization = ""+org;
	cert.issuerOrganization = ""+issuer;
	cert.sha1Fingerprint = ""+sha;
	return cert;
};

// Load us when the browser starts
window.addEventListener("load", function() {
	Components.classes["@mozilla.org/timer;1"].createInstance(Components.interfaces.nsITimer).initWithCallback(SSLNotifier.init, 500, Components.interfaces.nsITimer.TYPE_ONE_SHOT)
}, false);
// Unload us when the browser stops
window.addEventListener("unload", function() {SSLNotifier.exit();}, false);

// Register for page loads
var appcontent = document.getElementById("appcontent");   // browser
if(appcontent) {
  appcontent.addEventListener("DOMContentLoaded", SSLNotifier.onPageLoad, true);
}