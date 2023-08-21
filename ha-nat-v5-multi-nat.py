import logging
import socket
import boto3
import time
import os
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import random

logger = logging.getLogger()
# Can be adjusted to DEBUG, WARNING, ERROR based on needs
logger.setLevel(logging.INFO)

ec2_client = boto3.client('ec2', region_name=os.environ['AWS_REGION'])
autoscaling = boto3.client('autoscaling', region_name=os.environ['AWS_REGION'])

def is_port_open(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((ip, port))
        s.close()
        return True
    except socket.error:
        return False


def parse_input(input_data):
    return input_data.split(',') if isinstance(input_data, str) else input_data


def check_website_reachable(url, max_retries=2):
    parsed_url = urlparse(url)
    port = parsed_url.port if parsed_url.port else 443 if parsed_url.scheme == 'https' else 80

    retries = 0
    while retries < max_retries:
        if is_port_open(parsed_url.hostname, port):
            logger.info(f"{parsed_url.hostname}:{port} is reachable")
            return True
        retries += 1

    logger.warning(
        f"{parsed_url.hostname}:{port} is not reachable after {max_retries} retries")
    return False


def check_websites_reachable_concurrently(urls):
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(check_website_reachable, urls))
    return all(results)


def check_websites_reachable(urls, nat_instance_ids):
    urls = parse_input(urls)
    nat_instance_ids = parse_input(nat_instance_ids)

    route_tables = get_route_tables_by_tag('monitor')

    for nat_instance_id in nat_instance_ids:
        # Delete the 0.0.0.0/0 route only once at the beginning
        for route_table in route_tables:
            delete_route(route_table['RouteTableId'], "0.0.0.0/0")

        for route_table in route_tables:
            current_nat_id = False
            if not update_route_table(route_table['RouteTableId'], current_nat_id, nat_instance_id, '0.0.0.0/0'):
                logger.warning(
                    f"Route table {route_table['RouteTableId']} not updated correctly for NAT instance {nat_instance_id}, current_nat_id={current_nat_id}, nat_instance_id={nat_instance_id}.")
                return False

        logger.info(f"Using {nat_instance_id} to check")

        if check_websites_reachable_concurrently(urls):
            # Delete the 0.0.0.0/0 route only once after the check
            for route_table in route_tables:
                delete_route(route_table['RouteTableId'], "0.0.0.0/0")
            return True

    return False


def get_nat_instance_info(nat_instance_ids):
    response = ec2_client.describe_instances(
        Filters=[
            {'Name': 'instance-id', 'Values': nat_instance_ids}
        ]
    )
    return [
        {
            'NatInstanceId': instance['InstanceId'],
            'AvailabilityZone': instance['Placement']['AvailabilityZone']
        }
        for reservation in response['Reservations']
        for instance in reservation['Instances']
    ]


def get_route_tables_by_tag(tag_key):
    try:
        response = ec2_client.describe_route_tables(
            Filters=[{'Name': 'tag-key', 'Values': [tag_key]}]
        )
        return response['RouteTables']
    except Exception as e:
        logger.error(f"Error getting route table: {str(e)}")


def delete_route(route_table_id, destination_cidr_block):
    try:
        routes = ec2_client.describe_route_tables(RouteTableIds=[route_table_id])[
            'RouteTables'][0]['Routes']
        has_target_route = any(route.get(
            'DestinationCidrBlock') == destination_cidr_block for route in routes)
        if has_target_route:
            response = ec2_client.delete_route(
                RouteTableId=route_table_id,
                DestinationCidrBlock=destination_cidr_block
            )
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                return True
            else:
                logger.error(
                    f"Failed to delete route in RouteTable {route_table_id}.")
                return False
    except Exception as e:
        logger.error(f"Error deleting route: {str(e)}")
        return False


def update_route_table(route_table_id, current_nat_id, new_nat_id, destination_cidr_block):
    try:
        routes = ec2_client.describe_route_tables(RouteTableIds=[route_table_id])[
            'RouteTables'][0]['Routes']
        # Check if '0.0.0.0/0' route exists
        has_target_route = any(route.get(
            'DestinationCidrBlock') == destination_cidr_block for route in routes)
        if not has_target_route:
            ec2_client.create_route(
                RouteTableId=route_table_id,
                DestinationCidrBlock=destination_cidr_block,
                InstanceId=new_nat_id
            )
            new_instance_name=next((tag['Value'] for tag in ec2_client.describe_instances(InstanceIds=[new_nat_id])['Reservations'][0]['Instances'][0]['Tags'] if tag['Key'] == 'Name'), None)
            route_table_name = next((tag['Value'] for tag in ec2_client.describe_route_tables(RouteTableIds=[route_table_id])['RouteTables'][0]['Tags'] if tag['Key'] == 'Name'), None)
            logger.warning(
                f"Added {destination_cidr_block} route for {route_table_name} using NAT instance {new_instance_name}")
            return True
        elif new_nat_id and current_nat_id != new_nat_id:
            ec2_client.replace_route(
                RouteTableId=route_table_id,
                DestinationCidrBlock=destination_cidr_block,
                InstanceId=new_nat_id
            )
            if current_nat_id:
                old_instance_name = next((tag['Value'] for tag in ec2_client.describe_instances(InstanceIds=[current_nat_id])['Reservations'][0]['Instances'][0]['Tags'] if tag['Key'] == 'Name'), None)
            else:
                old_instance_name=None
            new_instance_name=next((tag['Value'] for tag in ec2_client.describe_instances(InstanceIds=[new_nat_id])['Reservations'][0]['Instances'][0]['Tags'] if tag['Key'] == 'Name'), None)
            route_table_name = next((tag['Value'] for tag in ec2_client.describe_route_tables(RouteTableIds=[route_table_id])['RouteTables'][0]['Tags'] if tag['Key'] == 'Name'), None)

            logger.warning(
                f"Replaced {destination_cidr_block} route for {route_table_name} with NAT instance {new_instance_name}, old one is {old_instance_name}")
            return True
    except Exception as e:
        logger.error(f"Error updating route table {route_table_id}: {str(e)}")
        return False


def get_nat_instances_from_autoscaling_group(autoscaling_group_name):
    autoscaling_client = boto3.client('autoscaling')
    ec2_client = boto3.client('ec2')

    try:
        response = autoscaling_client.describe_auto_scaling_instances(
            InstanceIds=[
                instance['InstanceId']
                for instance in autoscaling_client.describe_auto_scaling_groups(
                    AutoScalingGroupNames=[autoscaling_group_name]
                )['AutoScalingGroups'][0]['Instances']
            ]
        )

        # Get all instance IDs from the response
        all_instance_ids = [instance['InstanceId']
                            for instance in response['AutoScalingInstances']]

        # Describe the instances using the EC2 client
        ec2_response = ec2_client.describe_instances(
            InstanceIds=all_instance_ids, Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

        # Extracting the instance IDs from the response
        running_instance_ids = [instance['InstanceId']
                                for reservation in ec2_response['Reservations']for instance in reservation['Instances']]
        return running_instance_ids

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return []


def get_total_azs(tag_key):
    try:
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_route_tables(
            Filters=[{'Name': f"tag:{tag_key}", 'Values': ['*']}])
        azs = set()
        for route_table in response['RouteTables']:
            for association in route_table['Associations']:
                if 'SubnetId' in association:
                    subnet_response = ec2_client.describe_subnets(
                        Filters=[{'Name': 'subnet-id', 'Values': [association['SubnetId']]}])
                    for subnet in subnet_response['Subnets']:
                        azs.add(subnet['AvailabilityZone'])
        return len(azs)
    except Exception as e:
        logger.error(f"Error: {str(e)}")


def get_route_table_associated_subnet_az(route_table_id):
    try:
        response = ec2_client.describe_route_tables(
            Filters=[
                {'Name': 'route-table-id', 'Values': [route_table_id]}
            ]
        )

        if 'RouteTables' in response and response['RouteTables']:
            associations = response['RouteTables'][0].get('Associations')
            if associations:
                subnet_id = associations[0].get('SubnetId')
                if subnet_id:
                    subnet_response = ec2_client.describe_subnets(
                        Filters=[
                            {'Name': 'subnet-id', 'Values': [subnet_id]}
                        ]
                    )
                    if subnet_response['Subnets']:
                        return subnet_response['Subnets'][0]['AvailabilityZone']

        return None
    except Exception as e:
        logger.error(f"Error: {str(e)}")


def check_service_endpoint(service_name, region_name):
    endpoints = {
        'ec2': ec2_client.meta.endpoint_url,
        'autoscaling': autoscaling.meta.endpoint_url
    }

    endpoint = endpoints.get(service_name)
    parsed_url = urlparse(endpoint)
    port = parsed_url.port if parsed_url.port else 443 if parsed_url.scheme == 'https' else 80
    if not endpoint:
        logger.error(f"Service {service_name} is not supported in this function.")
        return False

    if is_port_open(parsed_url.hostname, port):
        return True
    else:
        logger.debug(f"{service_name} endpoint in {region_name} is NOT reachable on port 443.")
        return False


def handle_route_updates(healthy_nat_instances, route_table, subnet_az, assigned_instances):
    rt_instance = None
    new_nat_id=None
    logger.info(f"Begin to check: {route_table['RouteTableId']} ")
    need_adjust = True 
    logger.info(f"assigned_instances: {assigned_instances}")
    assigned_nat_instance = assigned_instances.get(route_table['RouteTableId'], None)
    logger.info(f"assigned_nat_instance: {assigned_nat_instance}")
    nat_instances_in_az = [nat for nat in healthy_nat_instances if nat['AvailabilityZone'] == subnet_az]
    logger.info(f"nat_instances_in_az: {nat_instances_in_az}")
    unassigned_in_az = [nat['NatInstanceId']for nat in nat_instances_in_az if nat['NatInstanceId'] not in assigned_instances.values()]
    other_az_instances = [nat for nat in healthy_nat_instances if nat['AvailabilityZone']!= subnet_az and nat['NatInstanceId'] not in assigned_instances.values()]
    logger.info(f"unassigned_in_az: {unassigned_in_az}")
    logger.info(f"healthy_nat_instances: {healthy_nat_instances}")
    # If current instance in the same AZ, does not need to change
    for route in route_table['Routes']:
      if route.get('DestinationCidrBlock', False) == '0.0.0.0/0':
        rt_instance = route.get('InstanceId', False)
        if rt_instance and rt_instance in [nat['NatInstanceId'] for nat in healthy_nat_instances] and rt_instance in [nat['NatInstanceId'] for nat in nat_instances_in_az]:
            if rt_instance in unassigned_in_az:
              need_adjust = False
              assigned_instances[route_table['RouteTableId']]=rt_instance
            unassigned_in_az = [nat['NatInstanceId']
                    for nat in nat_instances_in_az if nat['NatInstanceId'] not in assigned_instances.values()]
            logger.info(f"rt_instance: {rt_instance} in route_table_id: {route_table['RouteTableId']} does not need adjustment") 
        
    if need_adjust:
         # Try to find an unassigned NAT instance in the same AZ
      if unassigned_in_az:
        new_nat_id = random.choice(unassigned_in_az)
        assigned_instances[route_table['RouteTableId']] = new_nat_id
      else:
        # If no unassigned instances available, pick one healthy instance in the same AZ
        if nat_instances_in_az:
          new_nat_id = random.choice(nat_instances_in_az)['NatInstanceId']
          assigned_instances[route_table['RouteTableId']] = new_nat_id
        else:
            other_az_instances = [nat for nat in healthy_nat_instances if nat['AvailabilityZone']!= subnet_az and nat['NatInstanceId'] not in assigned_instances.values()]
            logger.info(f"other_az_instances: {other_az_instances}, subnet_az: {subnet_az}")
            logger.info(f"healthy_nat_instances: {healthy_nat_instances}")
            logger.info(f"assigned_instances: {assigned_instances}")
            logger.info(f"rt_instance: {rt_instance}")
          #  If current instance in other AZs, does not need to change
            if rt_instance and rt_instance in other_az_instances:
                need_adjust = False
                assigned_instances[route_table['RouteTableId']]=rt_instance
            else:
                # If no instance in the same AZ, pick one which is not assigned from other AZs
                other_az_instances = [nat for nat in healthy_nat_instances if nat['AvailabilityZone']!= subnet_az and nat['NatInstanceId'] not in assigned_instances.values()]
                if other_az_instances:
                  new_nat_id = random.choice(other_az_instances)['NatInstanceId']
                  assigned_instances[route_table['RouteTableId']] = new_nat_id
                else:
                    # if no unassigned fro other AZs, pick one healthy
                    if not other_az_instances:
                        if healthy_nat_instances:
                            new_nat_id = random.choice(healthy_nat_instances)['NatInstanceId']
                        else:
                           print("No healthy NAT instances available")

    if need_adjust and new_nat_id:
        update_route_table(route_table['RouteTableId'], rt_instance, new_nat_id, '0.0.0.0/0')

def tag_and_associate_eips(ec2_ids):
    try:
        # Get details of all EIPs
        all_eip_details = ec2_client.describe_addresses()
        
        # Filter EIPs with 'NAT:yes' tag
        nat_eips = [eip for eip in all_eip_details['Addresses'] if any(tag['Key'] == 'NAT' and tag['Value'] == 'yes' for tag in eip.get('Tags', []))]
        
        # Get a list of all provided EC2 instances
        response = ec2_client.describe_instances(InstanceIds=ec2_ids)
        instances = [instance for reservation in response['Reservations'] for instance in reservation['Instances']]
        
        # For each instance, check its EIP association
        for instance in instances:
            associated_eips = [eip for eip in all_eip_details['Addresses'] if eip.get('InstanceId') == instance['InstanceId']]
            
            if associated_eips:
                # Instance already has an EIP associated. Tag it with 'NAT:yes'
                for eip in associated_eips:
                    ec2_client.create_tags(Resources=[eip['AllocationId']], Tags=[{'Key': 'NAT', 'Value': 'yes'}])
            else:
                # Instance does not have an EIP. 
                # Try to find an available EIP with 'NAT:yes' tag
                available_nat_eips = [eip for eip in nat_eips if 'InstanceId' not in eip]
                
                if available_nat_eips:
                    # Associate the first available EIP with 'NAT:yes' tag
                    allocation_id = available_nat_eips[0]['AllocationId']
                    ec2_client.associate_address(InstanceId=instance['InstanceId'], AllocationId=allocation_id)
                else:
                    # No available EIP with 'NAT:yes' tag found. Allocate a new one.
                    allocation = ec2_client.allocate_address(Domain='vpc')
                    ec2_client.associate_address(InstanceId=instance['InstanceId'], AllocationId=allocation['AllocationId'])
                    ec2_client.create_tags(Resources=[allocation['AllocationId']], Tags=[{'Key': 'NAT', 'Value': 'yes'}])

        return f"Operation completed successfully."

    except Exception as e:
        return f"Error: {str(e)}"

def terminate_instances_based_on_status(instance_ids):
    try:
        # Get the status of the provided EC2 instances
        response = ec2_client.describe_instance_status(InstanceIds=instance_ids)
        
        # Filter instances that are not in 'initializing' status
        instances_to_terminate = [status['InstanceId'] for status in response['InstanceStatuses'] if status['InstanceStatus']['Status'] != 'initializing']
        
        if instances_to_terminate:
            # Terminate the instances
            logger.warning(f"Terminate unhealthy instances: {instances_to_terminate}")
            ec2_client.terminate_instances(InstanceIds=instances_to_terminate)
            return f"Terminated instances: {', '.join(instances_to_terminate)}"
        
        else:
            return "No instances to terminate based on the status."

    except Exception as e:
        return f"Error: {str(e)}"


def lambda_handler(event, context):
    website_urls = os.environ['WEBSITE_URLS'].split(',')
    autoscaling_group_name = os.environ['ASG_NAME']
    fixed_ip=os.environ['FIXED_IP']
    loop = True
    SERVICES_TO_CHECK = ['ec2', 'autoscaling']
    number_of_az = get_total_azs("nat-instance")
    assigned_instances = {}

    while loop and all([check_service_endpoint(service, os.environ['AWS_REGION']) for service in SERVICES_TO_CHECK]):
        nat_instances_ids = get_nat_instances_from_autoscaling_group(
            autoscaling_group_name)
        if not nat_instances_ids:
            logger.error("No NAT instances found!")
            return
        number_of_nat = len(nat_instances_ids)
        nat_instances = get_nat_instance_info(nat_instances_ids)
        nat_health_statuses = [check_websites_reachable(
            website_urls, nat_instance) for nat_instance in nat_instances_ids]
        healthy_nat_instances = [nat_instance for nat_instance, healthy in zip(
            nat_instances, nat_health_statuses) if healthy]
        logger.info(f"Healthy NAT instances info: {healthy_nat_instances}")
        route_tables = get_route_tables_by_tag('nat-instance')
        number_of_RTs = len(route_tables)
        logger.info(f"Total number of AZ used NAT: {number_of_az}")
        logger.info(f"Total number of avaiable NAT instances: {number_of_nat}")
        logger.info(
            f"Total number of route tables use NAT instances: {number_of_RTs}")
        for route_table in route_tables:
            subnet_az = get_route_table_associated_subnet_az(
                route_table['RouteTableId'])
            handle_route_updates(healthy_nat_instances, route_table, subnet_az, assigned_instances)
        
        unhealthy_nat_instances = [nat_instance for nat_instance, healthy in zip(
            nat_instances, nat_health_statuses) if not healthy]  
       
    
        if unhealthy_nat_instances:
            terminate_instances_based_on_status(instance['NatInstanceId'] for instance in unhealthy_nat_instances)
        
        healthy_ec2_ids=None
        
        if fixed_ip=="yes":
            if healthy_nat_instances:
                healthy_ec2_ids = [nat['NatInstanceId']for nat in healthy_nat_instances]
                tag_and_associate_eips(healthy_ec2_ids)
        loop = True
        