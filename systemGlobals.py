#
# Contains global state variables for scapyHunt.py
#
#

clientList = dict()
internalClientList = dict()
clientOpenPorts = dict()
macTable = 0
hubMode = False

knockSequence = 0

smtpSeqNumber = 0
smtpIsAlive = False

ftpSeqNumber = 0
ftpIsAlive = False
ftpUserEntered = False
ftpPassEntered = False
ftpUser = None
