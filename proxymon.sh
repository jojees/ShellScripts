#! /bin/bash
# Title     :proxymon.sh
# Comment   :This script updates AWS Cloudwatch Monitoring Service with success and failure rate of Squid Servers.
#            When the failure rate crosses the configured threshold, this script will trigger an alarm to terminate the instance.
# Author    :Joji Vithayathil Johny
# Date      :20160729
# Version   :0.1
# Usage     :bash proxymon.sh
# TestedOn  :GNU Bash, version 3.2.57(1)-release (x86_64-apple-darwin15)
# Notes     :Install Squidclient & AWS Cli to use this script. IAM role

# Define Variables here
PROXY_SUCCESS="0"
PROXY_FAILURES="0"
PROXY_REDIRECTION="0"
PROXY_MANAGER_PORT=81

# Identify Instance details
PROXY_HOSTNAME=$(curl http://169.254.169.254/latest/meta-data/hostname;echo)
PROXY_INSTANCEID=$(curl http://169.254.169.254/latest/meta-data/instance-id;echo)

# Function to categorize the response codes
# into success and failures

function categorize_status_code {
    STATUS_CODE_CHECK=$1
    if [[ $STATUS_CODE_CHECK == 2* ]]; then
        return '0'    # HTTP Success Response Codes
    elif [[ $STATUS_CODE_CHECK == 4* ]]; then
        return '1'    # HTTP Client Error Response Codes
    elif [[ $STATUS_CODE_CHECK == 5* ]]; then
        return '2'    # HTTP Server Error Response Codes
    elif [[ $STATUS_CODE_CHECK == 3* ]]; then
        return '3'    # HTTP Redirection Response Codes
    else
        return '4'    # Informational Response Codes
    fi
}

# Get squid statistics using squidclient based on HTTP Status codes
squidclient -p $PROXY_MANAGER_PORT mgr:forward  | grep -A1000 ^'Status' | grep -v ^'Status' > /tmp/$$.txt


# Process and identify the count of requests for each http status code.
while read line
do
    counter=1
    STATUS_CODE=""
    ATTEMPTS=""
	for i in $line
    do
	   if [ $counter == 1 ]
	   then
            STATUS_CODE=$i
            counter=`expr $counter + 1`
	   else
            ATTEMPTS=`expr $ATTEMPTS + $i`
	   fi
    done
    
    # Use only when needed to display attempts for each status code during each iteration.
    #echo "$STATUS_CODE -> $ATTEMPTS" 
    
    categorize_status_code $STATUS_CODE
        STATUS_CODE_TYPE=$?
        if [[ $STATUS_CODE_TYPE == 0 ]];then
            PROXY_SUCCESS=`expr $PROXY_SUCCESS + $ATTEMPTS`
        elif [[ $STATUS_CODE_TYPE == 1 ]];then
            PROXY_FAILURES=`expr $PROXY_FAILURES + $ATTEMPTS`
        elif [[ $STATUS_CODE_TYPE == 2 ]];then
            PROXY_FAILURES=`expr $PROXY_FAILURES + $ATTEMPTS`
        elif [[ $STATUS_CODE_TYPE == 3 ]];then
            PROXY_REDIRECTION=`expr $PROXY_REDIRECTION + $ATTEMPTS`
        else
        fi
done < /tmp/$$.txt

#echo "Redirections = $PROXY_REDIRECTION"
#echo "Failures = $PROXY_FAILURES"
#echo "Success = $PROXY_SUCCESS"

# Send Squid application metrics to CloudWatch
aws cloudwatch put-metric-data --region "$region" --namespace "SquidProxy" --metric-name "ProxyFailures" --unit "Count" --dimensions "StackName=$stackname" --value "\$PROXY_FAILURES" --timestamp "\`date -u "+%Y-%m-%dT%H:%M:%SZ"\`" 
aws cloudwatch put-metric-data --region "$region" --namespace "SquidProxy" --metric-name "ProxySuccess" --unit "Count" --dimensions "StackName=$stackname" --value "\$PROXY_SUCCESS" --timestamp "\`date -u "+%Y-%m-%dT%H:%M:%SZ"\`" 

# Trigger cloudwatch alert to terminate instance when failure rate crosses the configured threshold.

aws cloudwatch put-metric-alarm --alarm-name Proxy-FailureAlert --alarm-description "Terminate the instance when failure rate crosses the configured threshold." --namespace "AWS/EC2" --dimensions Name=InstanceId,Value="$PROXY_INSTANCEID" --statistic Maximum  --metric-name ProxyFailures --comparison-operator LessThanThreshold --threshold 1 --period 21600 --evaluation-periods 4 --alarm-actions arn:aws:automate:us-west-2:ec2:terminate


# Clean up stale/temporary files
rm -f /tmp/$$.txt