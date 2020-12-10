"""
This playbook searches the Corelight file logs for all transfers of a file designated in a CEF artifact named  fileHashSha1. By default, it uses a 7-day lookback window; this can be overridden by passing in a CEF artifact named startTime, with a numeric value representing the number of days to search.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'PopulateLookback' block
    PopulateLookback(container=container)

    return

"""
Prepare file query, using passed-in SHA1 and the lookback window from the previous function
"""
def format_file_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_file_query() called')
    
    template = """index=corelight sourcetype=corelight_files sha1={0} earliest=-{1}d@d | spath source | table ts dest_host src_host uid fuid mime_type bytes source"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.fileHashSha1",
        "PopulateLookback:custom_function:lookback",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_query")

    run_file_query(container=container)

    return

"""
Execute previously formatted query
"""
def run_file_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_file_query() called')

    # collect data for 'run_file_query' call
    formatted_data_1 = phantom.get_format_data(name='format_file_query')

    parameters = []
    
    # build parameters list for 'run_file_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-demo'], name="run_file_query")

    return

"""
Removes blank artifact values that show up in certain methods of creating an artifact
"""
def Artifact_Cleanup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Artifact_Cleanup() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashSha1", "!=", ""],
        ],
        name="Artifact_Cleanup:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_file_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Checks if a startTime CEF value was passed in. If so, use it for the lookback window in days within our query; if not, populate with a default of 7 days.
"""
def PopulateLookback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('PopulateLookback() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.startTime', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    PopulateLookback__lookback = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    if container_item_0[0] is None:
        PopulateLookback__lookback = 7
    else:
        PopulateLookback__lookback = container_item_0[0]
        
    phantom.debug(PopulateLookback__lookback)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='PopulateLookback:lookback', value=json.dumps(PopulateLookback__lookback))
    Artifact_Cleanup(container=container)

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