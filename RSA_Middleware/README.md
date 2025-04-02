**RSA_Middleware**

This is a work around for those applications which do not recognize CHALLENGE request sent to application for entering PASSCODE by RSA Authentication Manager during Radius authentication after providing USERNAME and PASSWORD

Pre-requisites

    1. Configure a linux server with Python3 and enable necessary firewall rules 
    2. Create a Radius Profile in RSA Authentication Manager in which provide the IP address of above configured server 
    3. Create a SHARED SECRET and share it wtih Application team along with the IP address of above server for configuring RADIUS authentication for the application. 
    4. Inform the application team to provide PASSWORDPASSCODE in the Password/Passcode section of RADIUS login 

Below values in the script should be replace with the actual values based on your configuration

    1. SHARED_SECRET_CONFIGURED_IN_RSA_FOR_THE_APPLICATION_HERE --> Shared Secret value configured in the application 
    2. RSA_AUTHENTICATION_MANAGER_SERVER_IP_HERE --> IP Address of your RSA Authentication Manager server 
