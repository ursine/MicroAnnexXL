-------------------------------------------------- 
README file for the CDROM
--------------------------------------------------
	
I.1 MOUNTING THE CDROM
	
	1. Log in as root to a host with a cdrom drive. This should be
	the same host as your installation host. If the installation host
	does not have a cdrom drive, then login to an NFS accessible
	host. 
	
	2. If necessary create a mount point for the cdrom:
	 # mkdir /cdrom
	
	If the volume manager mounts the cdrom, you can skip the
	next step. 

	 3. Mount the cdrom
	Please reference your system manual for details and instructions on
	mounting the CDROM on your specific system.
	
	The cdrom will contain the release tar file, this README
	file and the release notes. You do not need to copy the release
	tar file. You can access it directly through the /cdrom mount
	point. 

	 The <tape-dev> will be '/cdrom' (or equivalent). 
	 
I.2 STARTING THE SOFTWARE INSTALLATION FROM THE CDROM 
	
	1. Execute the installation program on the CDROM:
	# /cdrom/install 


II. INSTALLING ANNEX SOFTWARE AND ANNEX MANAGER
	
	1. To install the Annex Software and/or the Annex Manager,
	execute the "install" script on the CDROM.
	dewey# /cdrom/install
	 
	2. The script will ask the user whether the Annex Software or
	the Annex Manager is to be installed. After installing one product,
	the installation will prompt the user to install the other product,
	or the user may quit the installation. 

	
	************************************************************
	* *** It is required that you run this script as root. ***
	************************************************************
	# This command is used to install Annex Software (boot images, security, 
	# command line management) and Annex Manager (X-Motif GUI management 
	# application). 
	#
	#The versions that would be
	#installed are: 
	# Annex Software R10.1A
	# Annex Manager  R2.0
	#...
	...
	 
	At this point, the user selects whether to install the Annex
	Software or the Annex Manager. To install the Annex Software, the
	user enters "1" at the prompt; To install the Annex Manager, the
	user enters "2" at the prompt: 
	Indicate desired action:
	1) Install Annex Software
	2) Install Annex Manager
	
	The installation script will continue to install the Annex
	Manager and will prompt the user for information as necessary.
	For more information on the exact questions, please refer to the
	Installation Notes for the Annex Manager. 

	Please see the Install Notes for further details on installing the
	Annex Software and/or the Annex Manager.
	
