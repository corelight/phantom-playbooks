"""
This playbook collects a variety of Corelight-observed network indicators from a suspect IP address. By default, it provides details on all traffic for the past 7 days, with an optional whitelist of CIDR blocks (one per line) in a custom list named IPWhitelist. If called with an optional time stamp parameter, it also compares connections made for the 5 days prior to that time stamp to the connections made between the time stamp and now, highlighting connections to new systems and the layer 7 service present for those connections.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'MultiArtifact_StartTime' block
    MultiArtifact_StartTime(container=container)

    # call 'CalcLookbackWindow' block
    CalcLookbackWindow(container=container)

    return

"""
Calculate start of lookback window based on an offset from the current time. Window can be changed with the amount_to_modify and modification_unit items.
"""
def CalcLookbackWindow(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CalcLookbackWindow() called')
    
    literal_values_0 = [
        [
            -50,
            "days",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        parameters.append({
            'input_datetime': None,
            'amount_to_modify': item0[0],
            'modification_unit': item0[1],
            'input_format_string': None,
            'output_format_string': None,
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/datetime_modify", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='CalcLookbackWindow', callback=CalcLookbackWindow_callback)

    return

def CalcLookbackWindow_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('CalcLookbackWindow_callback() called')
    
    Format_External_IP_Query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Format_Internal_IP_Query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Format a query for all external connections from the suspect host between now and the previously calculated lookback window.
"""
def Format_External_IP_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_External_IP_Query() called')
    
    template = """index=corelight sourcetype=corelight_conn {0} local_resp=\"false\" earliest={1} latest=now() | table uid dest_ip id.resp_p resp_cc service"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
        "CalcLookbackWindow:custom_function_result.data.epoch_time",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_External_IP_Query")

    Execute_External_IP_Query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_External_IP_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_External_IP_Query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_External_IP_Query' call
    formatted_data_1 = phantom.get_format_data(name='Format_External_IP_Query')

    parameters = []
    
    # build parameters list for 'Execute_External_IP_Query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], callback=Remove_Whitelisted_IPs, name="Execute_External_IP_Query")

    return

"""
Format a query for all internal connections from the suspect host between now and the previously calculated lookback window.
"""
def Format_Internal_IP_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Internal_IP_Query() called')
    
    template = """index=corelight sourcetype=corelight_conn {0} local_resp=\"true\" earliest={1} latest=now() | fields uid dest_ip id.resp_p resp_cc service"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
        "CalcLookbackWindow:custom_function_result.data.epoch_time",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Internal_IP_Query")

    Execute_Internal_IP_Query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_Internal_IP_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_Internal_IP_Query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_Internal_IP_Query' call
    formatted_data_1 = phantom.get_format_data(name='Format_Internal_IP_Query')

    parameters = []
    
    # build parameters list for 'Execute_Internal_IP_Query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], callback=Execute_Internal_IP_Query_callback, name="Execute_Internal_IP_Query")

    return

def Execute_Internal_IP_Query_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('Execute_Internal_IP_Query_callback() called')
    
    Internal_Service_Filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Format_Software_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Switch to different queries/notes based on detected service type
"""
def Service_Branch(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Service_Branch() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:Remove_Whitelisted_IPs:condition_1:Execute_External_IP_Query:action_result.data.*.service", "==", "http"],
        ],
        name="Service_Branch:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_HTTP_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:Remove_Whitelisted_IPs:condition_1:Execute_External_IP_Query:action_result.data.*.service", "==", "ssl"],
        ],
        name="Service_Branch:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Format_SSL_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:Remove_Whitelisted_IPs:condition_1:Execute_External_IP_Query:action_result.data.*.service", "==", "dns"],
        ],
        name="Service_Branch:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        Format_DNS_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:Remove_Whitelisted_IPs:condition_1:Execute_External_IP_Query:action_result.data.*.service", "not in", "http,ssl,dns"],
        ],
        name="Service_Branch:condition_4")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        Format_service_note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    return

"""
Format a query to collect HTTP indicators
"""
def Format_HTTP_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_HTTP_query() called')
    
    template = """index=corelight sourcetype=corelight_http uid IN ({0}) | table uid method host uri status_code resp_mime_types user_agent"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Service_Branch:condition_1:Execute_External_IP_Query:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_HTTP_query")

    Execute_HTTP_query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_HTTP_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_HTTP_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_HTTP_query' call
    formatted_data_1 = phantom.get_format_data(name='Format_HTTP_query')

    parameters = []
    
    # build parameters list for 'Execute_HTTP_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], name="Execute_HTTP_query")

    return

"""
Format a query to collect SSL indicators
"""
def Format_SSL_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_SSL_query() called')
    
    template = """index=corelight sourcetype=corelight_ssl uid IN ({0}) | table uid subject validation_status version ja3 ja3s"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Service_Branch:condition_2:Execute_External_IP_Query:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_SSL_query")

    Execute_SSL_query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_SSL_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_SSL_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_SSL_query' call
    formatted_data_1 = phantom.get_format_data(name='Format_SSL_query')

    parameters = []
    
    # build parameters list for 'Execute_SSL_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], name="Execute_SSL_query")

    return

"""
Format a query to collect DNS indicators
"""
def Format_DNS_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_DNS_query() called')
    
    template = """index=corelight sourcetype=corelight_dns uid IN ({0}) | table uid query answers qtype_name rcode_name"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Service_Branch:condition_3:Execute_External_IP_Query:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_DNS_query")

    Execute_DNS_query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_DNS_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_DNS_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_DNS_query' call
    formatted_data_1 = phantom.get_format_data(name='Format_DNS_query')

    parameters = []
    
    # build parameters list for 'Execute_DNS_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], name="Execute_DNS_query")

    return

"""
Switch to different queries/notes based on detected service type
"""
def Internal_Service_Filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Internal_Service_Filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Execute_Internal_IP_Query:action_result.data.*.service", "==", "\"*smb*\""],
        ],
        name="Internal_Service_Filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_SMB_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Execute_Internal_IP_Query:action_result.data.*.service", "==", "\"*dce_rpc*\""],
        ],
        name="Internal_Service_Filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Format_DCE_RPC_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Execute_Internal_IP_Query:action_result.data.*.service", "==", "\"*ntlm*\""],
        ],
        name="Internal_Service_Filter:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        Format_NTLM_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Execute_Internal_IP_Query:action_result.data.*.service", "==", "dns"],
        ],
        name="Internal_Service_Filter:condition_4")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        Format_DNS_query_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    # collect filtered artifact ids for 'if' condition 5
    matched_artifacts_5, matched_results_5 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Execute_Internal_IP_Query:action_result.data.*.service", "not in", "\"*smb*\",\"*dce_rpc*\",\"*ntlm*\",dns"],
        ],
        name="Internal_Service_Filter:condition_5")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_5 or matched_results_5:
        Extra_service_branch(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_5, filtered_results=matched_results_5)

    return

"""
Format a query to collect SMB indicators
"""
def Format_SMB_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_SMB_query() called')
    
    template = """index=corelight path=corelight_smb_files uid IN({0}) | table uid dest_ip action name fuid"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Internal_Service_Filter:condition_1:Execute_Internal_IP_Query:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_SMB_query")

    Execute_SMB_query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_SMB_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_SMB_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_SMB_query' call
    formatted_data_1 = phantom.get_format_data(name='Format_SMB_query')

    parameters = []
    
    # build parameters list for 'Execute_SMB_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], callback=Format_SMB_Mappings_query, name="Execute_SMB_query")

    return

"""
Format a query for all software passively detected by Corelight in the previously calculated lookback window.
"""
def Format_Software_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Software_query() called')
    
    template = """index=corelight sourcetype=corelight_software | spath host | search host=\"{0}\""""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Software_query")

    Execute_Software_query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_Software_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_Software_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_Software_query' call
    formatted_data_1 = phantom.get_format_data(name='Format_Software_query')

    parameters = []
    
    # build parameters list for 'Execute_Software_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], callback=Format_Suricata_query, name="Execute_Software_query")

    return

"""
Format a query to collect details about SMB shares connected to
"""
def Format_SMB_Mappings_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_SMB_Mappings_query() called')
    
    template = """index=corelight path=corelight_smb_mapping uid IN({0}) | table uid dest_ip path service share_type"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Internal_Service_Filter:condition_1:Execute_Internal_IP_Query:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_SMB_Mappings_query")

    Execute_SMB_Mappings_query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_SMB_Mappings_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_SMB_Mappings_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_SMB_Mappings_query' call
    formatted_data_1 = phantom.get_format_data(name='Format_SMB_Mappings_query')

    parameters = []
    
    # build parameters list for 'Execute_SMB_Mappings_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], name="Execute_SMB_Mappings_query")

    return

"""
Format a query to collect NTLM indicators
"""
def Format_NTLM_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_NTLM_query() called')
    
    template = """index=corelight sourcetype=corelight_ntlm uid in ({0}) | table uid dest_ip domainname server_dns_computername server_nb_computername success"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Internal_Service_Filter:condition_3:Execute_Internal_IP_Query:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_NTLM_query")

    Execute_NTLM_query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_NTLM_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_NTLM_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_NTLM_query' call
    formatted_data_1 = phantom.get_format_data(name='Format_NTLM_query')

    parameters = []
    
    # build parameters list for 'Execute_NTLM_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], name="Execute_NTLM_query")

    return

"""
Format a query to collect DCE/RPC indicators
"""
def Format_DCE_RPC_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_DCE_RPC_query() called')
    
    template = """index=corelight sourcetype=corelight_dce_rpc uid in ({0}) | table uid dest_ip endpoint operation named_pipe"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Internal_Service_Filter:condition_2:Execute_Internal_IP_Query:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_DCE_RPC_query")

    Execute_DCE_RPC_query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_DCE_RPC_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_DCE_RPC_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_DCE_RPC_query' call
    formatted_data_1 = phantom.get_format_data(name='Format_DCE_RPC_query')

    parameters = []
    
    # build parameters list for 'Execute_DCE_RPC_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], name="Execute_DCE_RPC_query")

    return

"""
Format a query to collect DNS indicators
"""
def Format_DNS_query_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_DNS_query_2() called')
    
    template = """index=corelight sourcetype=corelight_dns uid IN ({0}) | table uid query answers qtype_name rcode_name"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Internal_Service_Filter:condition_4:Execute_Internal_IP_Query:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_DNS_query_2")

    Execute_DNS_query_2(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_DNS_query_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_DNS_query_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_DNS_query_2' call
    formatted_data_1 = phantom.get_format_data(name='Format_DNS_query_2')

    parameters = []
    
    # build parameters list for 'Execute_DNS_query_2' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], name="Execute_DNS_query_2")

    return

"""
Format a note indicating the presence of services beyond DNS, HTTP, or SSL, and the IP address of the remote device communicating over that service.
"""
def Format_service_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_service_note() called')
    
    template = """%%
Service detected: {0} on {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Service_Branch:condition_4:Execute_External_IP_Query:action_result.data.*.service",
        "filtered-data:Remove_Whitelisted_IPs:condition_1:Execute_External_IP_Query:action_result.data.*.dest_ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_service_note")

    Add_service_note(container=container)

    return

"""
Add previously configured note
"""
def Add_service_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_service_note() called')

    formatted_data_1 = phantom.get_format_data(name='Format_service_note')

    note_title = "External service detection"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
Optional whitelist for external IP addresses. Reads from Phantom built-in Custom List named IPWhitelist (if present), which is composed of CIDR blocks or single IP addresses, one per line.
"""
def Remove_Whitelisted_IPs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Remove_Whitelisted_IPs() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Execute_External_IP_Query:action_result.data.*.dest_ip", "not in", "custom_list:IPWhitelist"],
        ],
        name="Remove_Whitelisted_IPs:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Service_Branch(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Format a note indicating the presence of services beyond DNS, NTLM, SMB, or DCE/RPC, and the IP address of the remote device communicating over that service.
"""
def Format_other_service_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_other_service_note() called')
    
    template = """%%
Service detected: {0} on {1}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Internal_Service_Filter:condition_5:Execute_Internal_IP_Query:action_result.data.*.service",
        "filtered-data:Internal_Service_Filter:condition_5:Execute_Internal_IP_Query:action_result.data.*.dest_ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_other_service_note")

    Add_other_service_note(container=container)

    return

"""
Add previously configured note
"""
def Add_other_service_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_other_service_note() called')

    formatted_data_1 = phantom.get_format_data(name='Format_other_service_note')

    note_title = "Internal service detection"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
Only run comparative queries if a time of suspected compromise is supplied
"""
def MultiArtifact_StartTime(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('MultiArtifact_StartTime() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.startTime", "!=", ""],
        ],
        name="MultiArtifact_StartTime:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        CalcPreCompromiseTime(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Calculate start of lookback window based on an offset from suspected time of compromise. Window can be changed with the amount_to_modify and modification_unit items.
"""
def CalcPreCompromiseTime(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CalcPreCompromiseTime() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:MultiArtifact_StartTime:condition_1:artifact:*.cef.startTime'])
    literal_values_0 = [
        [
            -5,
            "days",
        ],
    ]

    parameters = []

    for item0 in filtered_artifacts_data_0:
        for item1 in literal_values_0:
            parameters.append({
                'input_datetime': item0[0],
                'amount_to_modify': item1[0],
                'modification_unit': item1[1],
                'input_format_string': None,
                'output_format_string': None,
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/datetime_modify", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='CalcPreCompromiseTime', callback=ConvertCompromiseTimeFormat)

    return

"""
Search for all connections made by suspect host in the configured time window prior to time of potential compromise. This example focuses on services, but see https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info for details on fields available for this analysis.
"""
def Format_PreCompromise_Service_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_PreCompromise_Service_Query() called')
    
    template = """index=corelight sourcetype=corelight_conn src_ip={2} earliest={0} latest={1} | table service dest_ip | stats count by service, dest_ip"""

    # parameter list for template variable replacement
    parameters = [
        "CalcPreCompromiseTime:custom_function_result.data.epoch_time",
        "ConvertCompromiseTimeFormat:custom_function_result.data.epoch_time",
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_PreCompromise_Service_Query")

    Execute_PreCompromise_Service_Query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_PreCompromise_Service_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_PreCompromise_Service_Query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_PreCompromise_Service_Query' call
    formatted_data_1 = phantom.get_format_data(name='Format_PreCompromise_Service_Query')

    parameters = []
    
    # build parameters list for 'Execute_PreCompromise_Service_Query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], callback=Format_PostCompromise_Service_Query, name="Execute_PreCompromise_Service_Query")

    return

"""
Use community built-in to convert to epoch timestamp
"""
def ConvertCompromiseTimeFormat(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ConvertCompromiseTimeFormat() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:MultiArtifact_StartTime:condition_1:artifact:*.cef.startTime'])

    parameters = []

    for item0 in filtered_artifacts_data_0:
        parameters.append({
            'input_datetime': item0[0],
            'amount_to_modify': None,
            'modification_unit': None,
            'input_format_string': None,
            'output_format_string': None,
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/datetime_modify", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='ConvertCompromiseTimeFormat', callback=Format_PreCompromise_Service_Query)

    return

"""
Search for all connections made by suspect host between the time of potential compromise and the current time. This example focuses on services, but see https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info for details on fields available for this analysis.
"""
def Format_PostCompromise_Service_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_PostCompromise_Service_Query() called')
    
    template = """index=corelight sourcetype=corelight_conn src_ip={0} earliest={1} latest=now() | table service dest_ip | stats count by service, dest_ip"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
        "ConvertCompromiseTimeFormat:custom_function_result.data.epoch_time",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_PostCompromise_Service_Query")

    Execute_PostCompromise_Service_Query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_PostCompromise_Service_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_PostCompromise_Service_Query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_PostCompromise_Service_Query' call
    formatted_data_1 = phantom.get_format_data(name='Format_PostCompromise_Service_Query')

    parameters = []
    
    # build parameters list for 'Execute_PostCompromise_Service_Query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], callback=New_Connections, name="Execute_PostCompromise_Service_Query")

    return

"""
Check to see if any systems connected to since the time of suspected compromise were not connected to in the configured lookback window prior to time of suspected compromise.
"""
def New_Connections(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('New_Connections() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Execute_PostCompromise_Service_Query:action_result.data.*.dest_ip", "not in", "Execute_PreCompromise_Service_Query:action_result.data.*.dest_ip"],
        ],
        name="New_Connections:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_New_Systems_Note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Format a note for any hosts connected to since the time of suspected compromise, but not in the configured pre-compromise time window. Includes IP address and service detected.
"""
def Format_New_Systems_Note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_New_Systems_Note() called')
    
    template = """New Host: {0} with service {1}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:New_Connections:condition_1:Execute_PostCompromise_Service_Query:action_result.data.*.dest_ip",
        "filtered-data:New_Connections:condition_1:Execute_PostCompromise_Service_Query:action_result.data.*.service",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_New_Systems_Note")

    Add_New_Systems_Note(container=container)

    return

"""
Add previously configured note
"""
def Add_New_Systems_Note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_New_Systems_Note() called')

    formatted_data_1 = phantom.get_format_data(name='Format_New_Systems_Note')

    note_title = "New System Connection"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def Extra_service_branch(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Extra_service_branch() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Execute_Internal_IP_Query:action_result.data.*.service", "==", "kerberos"],
        ],
        name="Extra_service_branch:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Kerberos_Query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Execute_Internal_IP_Query:action_result.data.*.service", "!=", ""],
        ],
        name="Extra_service_branch:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Format_other_service_note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Format a query to collect Kerberos indicators
"""
def Format_Kerberos_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Kerberos_Query() called')
    
    template = """index=corelight sourcetype=corelight_kerberos uid in ({0}) | table uid dest_ip client service request_type success cipher error_message"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Extra_service_branch:condition_1:Execute_Internal_IP_Query:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Kerberos_Query")

    Execute_Kerberos_query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_Kerberos_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_Kerberos_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_Kerberos_query' call
    formatted_data_1 = phantom.get_format_data(name='Format_Kerberos_Query')

    parameters = []
    
    # build parameters list for 'Execute_Kerberos_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], name="Execute_Kerberos_query")

    return

"""
Format a query to retrieve Suricata events triggered for system being investigated
"""
def Format_Suricata_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Suricata_query() called')
    
    template = """index=corelight sourcetype=corelight_suricata_corelight {0} earliest={1} latest=now() | table uid alert.signature alert.sid alert.severity dest_ip metadata alert.metadata"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
        "CalcLookbackWindow:custom_function_result.data.epoch_time",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Suricata_query")

    Execute_Suricata_query(container=container)

    return

"""
Execute previously formatted query
"""
def Execute_Suricata_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Execute_Suricata_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Execute_Suricata_query' call
    formatted_data_1 = phantom.get_format_data(name='Format_Suricata_query')

    parameters = []
    
    # build parameters list for 'Execute_Suricata_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], name="Execute_Suricata_query")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return