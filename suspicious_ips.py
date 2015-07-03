import re

class Log:
	def __init__(self, ipAddress, clientIdentity, userID, time, method, resource, protocol, statusCode, size):
		self.ipAddress = ipAddress
		self.clientIdentity = clientIdentity
		self.userID = userID
		self.time = time
		self.method = method
		self.resource = resource
		self.protocol = protocol
		self.statusCode = statusCode
		self.size = size
	
	@staticmethod
	def create_from_line(line):
		ipAddressPattern = '\d+\.\d+\.\d+\.\d+'
		clientIdentityPattern = '.*'
		userIDPattern = '\d+'
		timePattern = '.*'
		methodPattern = '\w+'
		resourcePattern = '.*'
		protocolPattern = '.*'
		statusCodePattern = '\d+'
		sizePattern = '\d+'
		linePattern = '({0}) ({1}) ({2}) \[({3})\] "({4}) ({5}) ({6})" ({7}) ({8})'.format(ipAddressPattern, clientIdentityPattern, userIDPattern, timePattern, methodPattern, resourcePattern, protocolPattern, statusCodePattern, sizePattern)
		result = re.match(linePattern, line)
		return Log(result.group(1), result.group(2), int(result.group(3)), result.group(4), result.group(5), result.group(6), result.group(7), int(result.group(8)), int(result.group(9)))

def get_logs(fileName):
	lines = None
	logs = []
	with open(fileName) as f:
		lines = f.readlines()
	for line in lines:
		logs.append(Log.create_from_line(line))
	return logs

def find_suspicious_ips(logFileName):
	logs = get_logs(logFileName)
	ipToTimes = get_ip_to_times_dict(logs)
	return get_suspicious_ips(ipToTimes)

def get_ip_to_times_dict(logs):
	ipToTimes = {}
	for log in logs:
		if is_suspicious_log(log):
			if not log.ipAddress in ipToTimes:
				ipToTimes[log.ipAddress] = {}
			if log.time in ipToTimes[log.ipAddress]:
				ipToTimes[log.ipAddress][log.time] += 1
			else:
				ipToTimes[log.ipAddress][log.time] = 1
	return ipToTimes

def is_suspicious_log(log):
	return 400 <= log.statusCode <= 499 and log.resource == "/account/withdraw"

def has_enough_failed_requests(timeToCount):
	for time in timeToCount:
		if timeToCount[time] >= 3:
			return True
	return False

def get_suspicious_ips(ipToTimes):
	suspiciousIPs = []
	for ipAddress in ipToTimes:
		if has_enough_failed_requests(ipToTimes[ipAddress]):
			suspiciousIPs.append(ipAddress)
	return suspiciousIPs
