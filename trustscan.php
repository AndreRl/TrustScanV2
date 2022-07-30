<?php

// Set some useful constants that the core may require or use
define("IN_MYBB", 1);
define('THIS_SCRIPT', 'trustscan.php');
require_once "./global.php";
require_once "./inc/plugins/trustscan.php";
add_breadcrumb('Trust Scan', "trustscan.php");

trustscan_securitycheck();

if($mybb->request_method === "post")
{

    verify_post_check($mybb->get_input('my_post_key'));
    $secondary = '';

    if($mybb->get_input('usersearch') && $mybb->get_input('searchuser'))
    {
        $user = get_user_by_username($mybb->input['usersearch'], array('fields' => 'uid, username, regip, lastip, usergroup, displaygroup'));
        trustscan_exclusioncheck($user['uid']);

        // Cross-check registration IP, last visit IP and all post IPs

        // Post IPs only for now...
        $postdata = array();
        $searchdata = array();
        $secondsearchdata = array();
        $regipdata = array();
        $lastipdata = array();
        $useripdata = array();

        $postipreference = $db->simple_select("posts", "*", "uid = ".$user['uid']."");
        if($db->num_rows($postipreference) >= 1)
        {

            while($rows = $db->fetch_array($postipreference))
            {
                $postdata[] = $rows;
            }

            $temp = array_unique(array_column($postdata, "ipaddress"));
            $postipreference = array_intersect_key($postdata, $temp);

            foreach($postipreference as $checkall)
            {
                $checkall['ipaddress'] = $db->escape_binary($checkall['ipaddress']);
                $search = $db->simple_select("posts", "*", "ipaddress = ".$checkall['ipaddress']." AND uid <> ".$user['uid']."");
                $secondsearch = $db->simple_select("users", "*", "regip = ".$checkall['ipaddress']." OR lastip = ".$checkall['ipaddress']."");

                if($db->num_rows($search) >= 1)
                {
                    while($rows = $db->fetch_array($search))
                    {
                        $searchdata[] = $rows;
                    }
                }

                if($db->num_rows($secondsearch) >= 1)
                {
                    while($rows = $db->fetch_array($secondsearch))
                    {
                        $secondsearchdata[] = $rows;
                    }
                }
            }

           // If results found on any of the above, merge into array 
        }

        $user['regip'] = $db->escape_binary($user['regip']);
        $user['lastip'] = $db->escape_binary($user['lastip']);

        $regipreference = $db->simple_select("posts", "*", "ipaddress = ".$user['regip']."");
        $lastipreference = $db->simple_select("posts", "*", "ipaddress = ".$user['lastip']."");
        $useripreference = $db->simple_select("users", "*", "(regip = ".$user['regip']." OR regip = ".$user['lastip'].") AND (uid <> ".$user['uid'].")");

        // Further merge into array and then list all of the above
        if($db->num_rows($regipreference) >= 1)
        {
            while($rows = $db->fetch_array($regipreference))
            {
                $regipdata[] = $rows;
            }
        }

        if($db->num_rows($lastipreference) >= 1)
        {
            while($rows = $db->fetch_array($lastipreference))
            {
                $lastipdata[] = $rows;
            }
        }

        if($db->num_rows($useripreference) >= 1)
        {
            while($rows = $db->fetch_array($useripreference))
            {
                $useripdata[] = $rows;
            }
        }

        $wholesearch = array_merge($searchdata, $secondsearchdata, $regipdata, $lastipdata, $useripdata);
        $temp = array_unique(array_column($wholesearch, 'uid'));
        /**NOTE TO SELF:
         
         */
        $wholesearch = array_intersect_key($wholesearch, $temp);
        $allips_listtemp = array();

        foreach($wholesearch as $eachresult)
        {

            if(isset($eachresult['ipaddress']))
            {
                $allips_listtemp[] = my_inet_ntop($eachresult['ipaddress']);
            }

            if(isset($eachresult['regip']))
            {
                $allips_listtemp[] = my_inet_ntop($eachresult['regip']);
            }

            if(isset($eachresult['lastip']))
            {
                $allips_listtemp[] = my_inet_ntop($eachresult['lastip']);
            }

            $avatar = "<img style=\"height: 100px;width:100px\"src=\"".$mybb->settings['bburl']."/".$eachresult['avatar']."\">";
            $link = $mybb->settings['bburl']."/".get_profile_link($eachresult['uid']);
            $username = format_name($eachresult['username'], $eachresult['usergroup'], $eachresult['displaygroup']);
            $uagent = $db->simple_select("sessions", "*", "uid = ".$eachresult['uid']."");
            if($db->num_rows($uagent) >= 1)
            {
                $uagent = $db->fetch_array($uagent);
                $useragentind = "<span class=\"smalltext\">User Agent: ".$uagent['useragent']." </span>";
            } else {
                $useragentind = '';
            }
            $recentip = "Last IP: ".my_inet_ntop($eachresult['lastip']);
            $regip = "Registration IP: ".my_inet_ntop($eachresult['regip']);
            eval("\$usersearched = \"".$templates->get("trustscan_ussocom_ipresults_box_details")."\";");
            eval("\$ip_results .= \"".$templates->get("trustscan_ussocom_ipresults_box")."\";");
        }

        $allips_listtemp = array_unique($allips_listtemp);

        foreach($allips_listtemp as $indivip)
        {
            $allips_list .= $linebreak.$indivip;
            $linebreak = "<br />";
        }


        $user['avatar'] = "<img style=\"max-height: 100px;max-width:100px\"src=\"".$mybb->settings['bburl']."/".$user['avatar']."\">";
        $userlink = $mybb->settings['bburl']."/".get_profile_link($user['uid']);
        $user['username'] = format_name($user['username'], $user['usergroup'], $user['displaygroup']);
        $user['allips'] = '<a href="#" onclick="$(\'#allips\').modal({ fadeDuration: 250, keepelement: true, zIndex: (typeof modal_zindex !== \'undefined\' ? modal_zindex : 9999) }); return false;">All IPs</a>';
        $user['info'] = "<a href=\"$userlink\">$avatar<br />".$user['username']."</a><br />".$user['allips']."";

        $user['agent'] = $db->simple_select("sessions", "useragent", "uid = ".$user['uid']."");
        eval("\$userinfo = \"".$templates->get("trustscan_ussocom_userinfo")."\";");

        if($db->num_rows($user['agent']) >= 1)
        {
            $user['agent'] = $db->fetch_field($user['agent'], "useragent");
            $useragent = "<br /><span class=\"smalltext\">User Agent: ".$user['agent']." </span>";
        }

        $secondary = "usercheck";

    }else if($mybb->get_input('ipsearch') && $mybb->get_input('searchip'))
    {
        if(!filter_var($mybb->get_input('ipsearch'), FILTER_VALIDATE_IP))
        {
            error("Not a valid IP.");
        }

        $firstsearch = $db->simple_select("users", "*", "regip = ".$db->escape_binary(my_inet_pton($mybb->get_input('ipsearch')))." OR lastip = ".$db->escape_binary(my_inet_pton($mybb->get_input('ipsearch')))."");
        $secondsearch = $db->simple_select("posts", "*", "ipaddress = ".$db->escape_binary(my_inet_pton($mybb->get_input('ipsearch')))."");

        $matchedusers = array();
        $matchedposts = array();

        if($db->num_rows($firstsearch) >= 1)
        {
            while($usersearch = $db->fetch_array($firstsearch))
            {
                $matchedusers[] = $usersearch;
            }
        }

        if($db->num_rows($secondsearch) >= 1)
        {
            while($postsearch = $db->fetch_array($secondsearch))
            {
                $matchedposts[] = $postsearch;
            }
        }

        $wholesearch = array_merge($matchedusers, $matchedposts);
        $temp = array_unique(array_column($wholesearch, 'uid'));
        $wholesearch = array_intersect_key($wholesearch, $temp);

        if(isset($wholesearch))
        {
            
            $lookupresults = trustscan_lookup($mybb->get_input('ipsearch'));

            switch($lookupresults['security']['proxy'])
            {
                case 1:
                    $lookupresults['security']['proxy'] = "True";
                    break;
                default:
                $lookupresults['security']['proxy'] = "False";
            }

            switch($lookupresults['security']['vpn'])
            {
                case 1:
                    $lookupresults['security']['vpn'] = "True";
                    break;
                default:
                $lookupresults['security']['vpn'] = "False";
            }

            switch($lookupresults['security']['tor'])
            {
                case 1:
                    $lookupresults['security']['tor'] = "True";
                    break;
                default:
                $lookupresults['security']['tor'] = "False";
            }

            $lookupresults['country'] = $lookupresults['location']['country'];
            $lookupresults['latitude'] = $lookupresults['location']['latitude'];
            $lookupresults['longitude'] = $lookupresults['location']['longitude'];

            eval("\$ipinfo = \"".$templates->get("trustscan_ussocom_ipinfo")."\";");
            // List users
            foreach($wholesearch as $eachresult)
            {
                $crosseduser = get_user($eachresult['uid']);
                $avatar = "<img style=\"height: 100px;width:100px\"src=\"".$mybb->settings['bburl']."/".$crosseduser['avatar']."\">";
                $link = $mybb->settings['bburl']."/".get_profile_link($crosseduser['uid']);
                $username = format_name($crosseduser['username'], $crosseduser['usergroup'], $crosseduser['displaygroup']);
                $uagent = $db->simple_select("sessions", "useragent", "uid = ".$crosseduser['uid']."");
                if($db->num_rows($uagent) >= 1)
                {
                    $uagent = $db->fetch_field($uagent, "useragent");
                    $useragentind = "<br /><span class=\"smalltext\">User Agent: ".$uagent." </span>";
                } else {
                    $useragentind = '';
                }
                $recentip = "Last IP: ".my_inet_ntop($crosseduser['lastip']);
                $regip = "Registration IP: ".my_inet_ntop($crosseduser['regip']);
                //$user = "<a href=\"$link\">$avatar<br />$username<br /></a>$recentip $useragentind";
                eval("\$useripinfo = \"".$templates->get("trustscan_ussocom_ipresults_useripinfo")."\";");
                eval("\$ip_results .= \"".$templates->get("trustscan_ussocom_ipresults")."\";");
            }

            $secondary = "ipcheck";
        }
        

    }
}

switch($secondary)
{
    case "usercheck":
        eval("\$html = \"".$templates->get("trustscan_ussocom_ipcheck")."\";"); 
        break;
    case "ipcheck":
        eval("\$html = \"".$templates->get("trustscan_ussocom_ipcheck")."\";"); 
        break;
    default:
    eval("\$html = \"".$templates->get("trustscan_ussocom")."\";"); 
} 
output_page($html);
?>
