#!/bin/bash

# This script takes-over the EIP defined in the variable and assigns it over to the eth1 of the host instance.
# Author: Joji Vithayathil Johny
# Version: 0.1
# Usage: bash transferEIP.sh
# Notes: This scripts assumes that: 
#		eth1 is configured
#		EIP already exists & assigned to another host/vm/instance
#		host running this script has instance role assigned along with required permissions

# Reading common variables
source /etc/profile
source /etc/environment

# Variables for the script
EIP=52.43.121.147
INSTANCE_ID=`curl -s 169.254.169.254/latest/meta-data/instance-id`
REGION_ID=`curl -s 169.254.169.254/latest/meta-data/placement/availability-zone/|sed 's|\([a-z]*-[a-z]*-[0-9]\)[a-z]*|\1|'`
NTW_INTF_ETH1=`ifconfig eth1 | awk '/inet addr/{print substr($2,6)}'`

# Gather information regarding Allocation ID
ALLOCATION_ID=`aws ec2 describe-network-interfaces --region ${REGION_ID} --filter "Name=addresses.association.public-ip,Values=${EIP}"| grep -i -m 1 AllocationID |sed 's|\ ||g; s|\"||g; s|\,||g' | cut -d ":" -f 2`

# Gather information regarding Network Interface ID
NTW_INTF_ID=`aws ec2 describe-network-interfaces --region ${REGION_ID} --filter "Name=addresses.private-ip-address,Values=${NTW_INTF_ETH1}" --query 'NetworkInterfaces[0].{NWINF:NetworkInterfaceId}'|sed 's|[{}]||g; s|\ ||g; /^[[:space:]]*$/d; s|\"||g'|cut -d ":" -f 2`

# Start executing the transfer of EIP
echo "Taking over the EIP(${EIP}) onto instance(${INSTANCE_ID})"
echo "Applying EIP to Private IP Address: $NTW_INTF_ETH1"
echo "Network Interface ID is: $NTW_INTF_ID"
aws ec2 associate-address --region ${REGION_ID} --allocation-id ${ALLOCATION_ID} --network-interface-id ${NTW_INTF_ID} --allow-reassociation

# Validate if the EIP transfer was complete
EIP_ASSIGNED=`aws ec2 describe-network-interfaces --region ${REGION_ID} --filter "Name=addresses.private-ip-address,Values=${NTW_INTF_ETH1}" --query 'NetworkInterfaces[0].[PrivateIpAddresses[0].Association.PublicIp]'|sed 's|\[||g; s|\]||g; /^[[:space:]]*$/d; s|\ ||g; s|\"||g'`

echo "Assigned EIP is: $EIP_ASSIGNED"

if [[ $EIP_ASSIGNED == $EIP ]]
then
	echo "EIP transfer is successful."
else
	echo -e "$(tput setaf 1)EIP transfer is not successful.\nPlease transfer manually.$(tput sgr 0)"
fi

