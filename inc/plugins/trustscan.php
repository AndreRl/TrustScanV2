<?php

// Disallow direct access to this file for security reasons
if(!defined("IN_MYBB"))
{
	die("Direct initialization of this file is not allowed.");
}


function trustscan_info()
{
	return array(
        "name"  => "Trust Scan V2",
        "description"=> "An in-depth security check on selected personnel.",
        "website"        => "https://github.com/AndreRl",
        "author"        => "Wires <i>(AndreRl)</i>",
        "authorsite"    => "https://github.com/AndreRl",
        "version"        => "1.0",
        "guid"             => "",
        "compatibility" => "18*"
    );
}

function trustscan_install()
{
    global $db, $mybb;

    $setting_group = array(
        'name' => 'trustscan_settings',
        'title' => 'Trust Scan Settings',
        'description' => 'Configure how in-depth security should be.',
        'disporder' => 5,
        'isdefault' => 0
    );
    
    $gid = $db->insert_query("settinggroups", $setting_group);

    $setting_array = array(
        'trustscan_enable' => array(
            'title' => 'Enable Plugin',
            'description' => 'Enable the entire plugin.',
            'optionscode' => 'yesno',
            'value' => 1,
            'disporder' => 1
        ),
        'trustscan_exclusion' => array(
            'title' => 'Limitations',
            'description' => 'Which groups are to be excluded from security checks?',
            'optionscode' => "groupselect",
            'value' => "",
            'disporder' => 2
        ),
        'trustscan_apikey' => array(
            'title' => 'IP Check API',
            'description' => 'Register to vpnapi.io and place your own API Key here!',
            'optionscode' => "text",
            'value' => "a93055e6dafb491ca242142abdc4f0e6",
            'disporder' => 3
        ),
    );
    
    foreach($setting_array as $name => $setting)
    {
        $setting['name'] = $name;
        $setting['gid'] = $gid;
    
        $db->insert_query('settings', $setting);
    }
    
    rebuild_settings();
    
    
}

function trustscan_is_installed()
{
    global $mybb;
    if(isset($mybb->settings['trustscan_enable']))
    {
        return true;
    } 
        return false;
}

function trustscan_uninstall()
{
    global $db;

    $db->delete_query('settings', "name LIKE 'trustscan_%'");
    $db->delete_query('settinggroups', "name = 'trustscan_settings'");
    
    rebuild_settings();
    
}

function trustscan_activate()
{
    global $db;

    $trustscan_ipinfo_template = '(Possible) Proxy: {$lookupresults[\'security\'][\'proxy\']} | (Possible) VPN: {$lookupresults[\'security\'][\'vpn\']} | (Possible) Tor: {$lookupresults[\'security\'][\'tor\']} | Provider: {$lookupresults[\'network\'][\'autonomous_system_organization\']} | Country: {$lookupresults[\'location\'][\'country\']} | Latitude & Longitude: {$lookupresults[\'location\'][\'latitude\']} & {$lookupresults[\'location\'][\'longitude\']}<br /><br />Searched & Matched IP: {$mybb->input[\'ipsearch\']}';

    $trustscan_ipinfo_array = array(
        'title' => 'trustscan_ussocom_ipinfo',
        'template' => $db->escape_string($trustscan_ipinfo_template),
        'sid' => '-1',
        'version' => '',
        'dateline' => time()
    );
    
    $db->insert_query('templates', $trustscan_ipinfo_array);

    $trustscan_userinfo_template = 'You are currently looking up: <br /><br />{$user[\'info\']} {$useragent}';

        $trustscan_userinfo_array = array(
            'title' => 'trustscan_ussocom_userinfo',
            'template' => $db->escape_string($trustscan_userinfo_template),
            'sid' => '-1',
            'version' => '',
            'dateline' => time()
        );
        
        $db->insert_query('templates', $trustscan_userinfo_array);

        $trustscan_ipresults_template = '<div class="secprofiles"style="width: 30%;padding:20px;margin-bottom:2rem;display:flex;background-color:#21252b;border-radius:5px;overflow:scroll">{$useripinfo}</div>';

        $trustscan_ipresults_array = array(
            'title' => 'trustscan_ussocom_ipresults',
            'template' => $db->escape_string($trustscan_ipresults_template),
            'sid' => '-1',
            'version' => '',
            'dateline' => time()
        );
        
        $db->insert_query('templates', $trustscan_ipresults_array);

        $trustscan_ipresults_useripinfo_template = '<div><a href="{$link}">{$avatar}</a></div><div style="padding-left:20px;"><a href="{$link}">{$username}</a><hr>{$recentip}<br />{$regip}<br /><br /> {$useragentind}<br /><br /><a href=""><img style="width:25px;height:25px" src="https://i.ibb.co/BT2nG7z/SOCOM.png"></a> <a href=""><img style="width:25px;height:25px" src="https://i.imgur.com/aQYjw2H.png"></a> <a href=""><img style="width:25px;height:25px" src="https://i.ibb.co/d5S6MVC/OJSIG2.png"></a></div>';

        $trustscan_ipresults_useripinfo_array = array(
            'title' => 'trustscan_ussocom_ipresults_useripinfo',
            'template' => $db->escape_string($trustscan_ipresults_useripinfo_template),
            'sid' => '-1',
            'version' => '',
            'dateline' => time()
        );
        
        $db->insert_query('templates', $trustscan_ipresults_useripinfo_array);

        $trustscan_ipresults_box_template = '<div class="secprofiles"style="width: 30%;padding:20px;margin-bottom:2rem;display:flex;background-color:#21252b;border-radius:5px;overflow:scroll">{$usersearched}</div>';

        $trustscan_ipresults_box_array = array(
            'title' => 'trustscan_ussocom_ipresults_box',
            'template' => $db->escape_string($trustscan_ipresults_box_template),
            'sid' => '-1',
            'version' => '',
            'dateline' => time()
        );
        
        $db->insert_query('templates', $trustscan_ipresults_box_array);

        $trustscan_ipresults_box_details_template = '<div><a href="{$link}">{$avatar}</a></div><div style="padding-left:20px;"><a href="{$link}">{$username}</a><hr>{$recentip}<br />{$regip}<br /><br /> {$useragentind}<br /><br /><a href=""><img style="width:25px;height:25px" src="https://i.ibb.co/BT2nG7z/SOCOM.png"></a> <a href=""><img style="width:25px;height:25px" src="https://i.imgur.com/aQYjw2H.png"></a> <a href=""><img style="width:25px;height:25px" src="https://i.ibb.co/d5S6MVC/OJSIG2.png"></a></div>';

        $trustscan_ipresults_box_details_array = array(
            'title' => 'trustscan_ussocom_ipresults_box_details',
            'template' => $db->escape_string($trustscan_ipresults_box_details_template),
            'sid' => '-1',
            'version' => '',
            'dateline' => time()
        );
        
        $db->insert_query('templates', $trustscan_ipresults_box_details_array);

    $trustscan_template = '<html>
    <head>
    <title>{$mybb->settings[\'bbname\']} - Trust Scan</title>
    {$headerinclude}
    </head>
    <body>
    {$header}
<div id="content_width" style="width:98%;">
<td valign="top">
<form method="post">
<input type="hidden" name="my_post_key" value="{$mybb->post_code}" />
<input type="hidden" name="action" value="security_check" />
<table border="0" cellspacing="{$theme[\'borderwidth\']}" cellpadding="{$theme[\'tablespace\']}" class="tborder">
<tr>
<td class="thead" colspan="2"><strong>United States Special Operations Command (USSOCOM)</strong></td>
</tr>
<tr><td class="trow1" colspan="2">Welcome {$mybb->user[\'username\']}, <br /><br /></td></tr>
<tr class="trow1" style="text-align:center">
<td><center><input class="textbox" type="text" placeholder="Enter Username" name="usersearch" id="usersearch" value="" /><br /><br />
    <input type="submit" class="button" name="searchuser" value="Search User" /></center></td>
<td><center><input class="textbox" type="text" placeholder="Enter IP Address" name="ipsearch" value="" /><br /><br />
    <input type="submit" class="button" name="searchip" value="Search IP" /></center></td>
</tr>
</table>
</form>
</td>
	</div>
    {$footer}
    <link rel="stylesheet" href="{$mybb->asset_url}/jscripts/select2/select2.css?ver=1807">
<script type="text/javascript" src="{$mybb->asset_url}/jscripts/select2/select2.min.js?ver=1806"></script>
<script type="text/javascript">
<!--
if(use_xmlhttprequest == "1")
{
	MyBB.select2();
	$("#usersearch").select2({
		placeholder: "{$lang->search_user}",
		minimumInputLength: 2,
		multiple: false,
		allowClear: true,
		ajax: { // instead of writing the function to execute the request we use Select2\'s convenient helper
			url: "xmlhttp.php?action=get_users",
			dataType: \'json\',
			data: function (term, page) {
				return {
					query: term, // search term
				};
			},
			results: function (data, page) { // parse the results into the format expected by Select2.
				// since we are using custom formatting functions we do not need to alter remote JSON data
				return {results: data};
			}
		},
		initSelection: function(element, callback) {
			var value = $(element).val();
			if (value !== "") {
				callback({
					id: value,
					text: value
				});
			}
		},
       // Allow the user entered text to be selected as well
       createSearchChoice:function(term, data) {
			if ( $(data).filter( function() {
				return this.text.localeCompare(term)===0;
			}).length===0) {
				return {id:term, text:term};
			}
		},
	});

  	$(\'[for=usersearch]\').on(\'click\', function(){
		$("#usersearch").select2(\'open\');
		return false;
	});
}
// -->
</script>
    </body>
    </html>';

    $trustscan_array = array(
        'title' => 'trustscan_ussocom',
        'template' => $db->escape_string($trustscan_template),
        'sid' => '-1',
        'version' => '',
        'dateline' => time()
    );
    
    $db->insert_query('templates', $trustscan_array);

    $trustscan_ipcheck_template = '<html>
    <head>
    <title>{$mybb->settings[\'bbname\']} - Trust Scan</title>
    {$headerinclude}
    </head>
    <body>
    {$header}
<div id="content_width" style="width:98%;">
<td valign="top">
<table border="0" cellspacing="{$theme[\'borderwidth\']}" cellpadding="{$theme[\'tablespace\']}" class="tborder">
<tr>
    <th class="thead" colspan="1"><div class="float_left"><div><strong>United States Special Operations Command (USSOCOM)</strong></div></div></th>
</tr>
<tr class="trow1">
<td colspan="1">
        Welcome {$mybb->user[\'username\']}, <br /><br />
        <center>{$ipinfo}{$userinfo}</center>
</td>
</tr>
<tr class="trow1" style="text-align: center">
<td><div style="display: flex;flex-flow:wrap;justify-content:space-between">{$ip_results}</div></td>
</tr>
</table>
</td>
	</div>
    <div class="modal" id="allips" style="display: none;text-align:center;">
        <table width="100%" cellspacing="{$theme[\'borderwidth\']}" cellpadding="{$theme[\'tablespace\']}" border="0" class="tborder">
            <tr>
                <td class="thead" colspan="2"><strong>All IPs for {$user[\'username\']}</strong></td>
            </tr>
            <tr>
                <td class="trow1" colspan="2"></td>
            </tr>
            <tr>
                <td class="trow1" colspan="2">{$allips_list}</td>
            </tr>
            <tr>
                <td class="trow1" colspan="2"></td>
            </tr>
        </table>
    </form>
</div>
<script type="text/javascript">
    $("#allips input[name=\'url\']").val($(location).attr(\'href\'));
</script>
    {$footer}
    </body>
    </html>';

    $trustscan_ipcheck_array = array(
        'title' => 'trustscan_ussocom_ipcheck',
        'template' => $db->escape_string($trustscan_ipcheck_template),
        'sid' => '-1',
        'version' => '',
        'dateline' => time()
    );
    
    $db->insert_query('templates', $trustscan_ipcheck_array);

}

function trustscan_deactivate()
{
    global $db;

    $db->delete_query('templates', "title LIKE 'trustscan_%'");
}

function trustscan_securitycheck ()
{
    global $mybb;

    if($mybb->settings['trustscan_enable'] != 1 || !is_member("39,98"))
{
    error_no_permission();
}

}

function trustscan_exclusioncheck ($uid)
{
    global $mybb;

    $exclusions = $mybb->settings['trustscan_exclusion'];
    $exclusions = explode(",", $exclusions);

    foreach($exclusions as $exclusion)
    {
        if(is_member($exclusion, $uid))
        {
            error("A security check cannot be performed on this user.");
        }
    }
}

function trustscan_lookup($ip)
{
    global $mybb;

$curl = curl_init();
curl_setopt($curl, CURLOPT_URL, "https://vpnapi.io/api/$ip?key=".$mybb->settings['trustscan_apikey']."");
curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
$lookupresults = curl_exec($curl);
$lookupresults = json_decode($lookupresults, true);
curl_close($curl);
return $lookupresults;
}