feed_template = '''
<html>
  <head>
    <title>Carbon Black {{integration_name}} Feed</title>

    <style type="text/css">
    A:link {color: black;}
    A:visited {color: black;}
    A:active {color: black;}
    A:hover {underline; color: #d02828;}
    </style>

    <style>
    #config
    {
    font-family:"Trebuchet MS", Arial, Helvetica, sans-serif;
    width:100%;
    border-collapse:collapse;
    }
    #config td, #config th
    {
    font-size:1em;
    border:1px solid #000000;
    padding:3px 7px 2px 7px;
    }
    #config th
    {
    font-size:1.1em;
    text-align:left;
    padding-top:5px;
    padding-bottom:4px;
    background-color:#d02828;
    color:#ffffff;
    }
    #config tr.alt td
    {
    color:#000000;
    background-color:#666666;
    }
    </style>
  </head>
  <body bgcolor='white'>
    <table align='center'>
      <tr>
        <td>
          <h3>
            Feed Reports
          </h3>
          <table id="config" align='center'>
            <tr>
               <th><b>ReportId</b></td>
               <th><b>ReportTitle</b></td>
               <th><b>Timestamp</b></td>
               <th><b>Score</b></td>
               <th><b>IOCs</b></td>
            </tr>
            {% for report in feed['reports'] %}
            <tr class={{loop.cycle('', 'alt')}}>
              <td><a href={{report['link']}}>{{report['id']}}</a></td>
              <td>{{report['title']}}</td>
              <td>{{report['timestamp']}}</td>
              <td>{{report['score']}}</td>
              <td>
                 {% for md5 in report.get('iocs', {}).get('md5', []) %}
                     {{md5}}<br>
                 {% endfor %}
                 {% for dns in report.get('iocs', {}).get('dns', []) %}
                     {{dns}}<br>
                 {% endfor %}
                 {% for ipv4 in report.get('iocs', {}).get('ipv4', []) %}
                     {{ipv4}}<br>
                 {% endfor %}
              </td>
            </tr>
            {% endfor %}
          </table>
          <br>
      <tr>
        <td>Copyright Carbon Black 2015 All Rights Reserved</td>
      </tr>
    </table>
  </body>
</html>
'''

index_template = '''
<html>
  <head>
    <title>Carbon Black <-> {{integration_name}} Bridge</title>

    <style type="text/css">
    A:link {color: black;}
    A:visited {color: black;}
    A:active {color: black;}
    A:hover {color: #d02828;}
    </style>

    <style>
    #config
    {
    font-family:"Trebuchet MS", Arial, Helvetica, sans-serif;
    width:100%;
    border-collapse:collapse;
    }
    #config td, #config th
    {
    font-size:1em;
    border:1px solid #000000;
    padding:3px 7px 2px 7px;
    }
    #config th
    {
    font-size:1.1em;
    text-align:left;
    padding-top:5px;
    padding-bottom:4px;
    background-color:#d02828;
    color:#ffffff;
    }
    #config tr.alt td
    {
    color:#000000;
    background-color:#666666;
    }
    </style>
  </head>
  <body bgcolor='white'>
    <table align='center' width='600'>
     <tr>
         <td align='center'><img src='{{cb_image_path}}'></td>
         <td align='center'><img src='{{integration_image_path}}' width='400'></td>
      </tr>
    </table>

    <br>

    <table align='center' width='600'>
      <tr>
        <td>

          <h3>
            Bridge Configuration
          </h3>
          <table id="config" align='center'>
            <tr>
               <th width='200'><b>Config Option</b></td>
               <th width='300'><b>Value</b></td>
            </tr>
            {% for option in options.keys() %}
            <tr class={{loop.cycle('', 'alt')}}>
              <td>{{option}}</td>
              <td>{{options[option]}}</td>
            </tr>
            {% endfor %}
          </table>

          <br>

          <h3>
            Feed Information
          </h3>
          <table id="config" align='center'>
            <tr>
              <th width='200'><b>Feed Param Name</b></td>
              <th width-'300'><b>Feed Param Value</b></td>
            </tr>
            {% for feedparamname in feed['feedinfo'].keys() %}
            <tr class={{ loop.cycle('', 'alt') }}>
              <td width='200'>{{feedparamname}}</td>
              <td width='300'>{{feed['feedinfo'][feedparamname]}}</td>
            </tr>
            {% endfor %}
          </table>

          <br>

          <h3>
            Feed Contents
          </h3>

          <table id="config" align='center'>
            <tr>
              <th width='200'>Format</td>
              <th width='300'>Description</td>
            </tr>
            <tr>
              <td width='200'><a href='{{json_feed_path}}'>JSON</a></td>
              <td width='300'>Designed for programmatic consumption; used by Carbon Black Enterprise Server</td>
            </tr>
            <tr class='alt'>
              <td width='200'><a href='feed.html'>HTML</a></td>
              <td width='300'>Designed for human consumption; used to explore feed contents and for troubleshooting</td>
            </tr>
          </table>
        </td>
      </tr>
      <tr>
        <td><br></td>
      </tr>
      <tr>
        <td>Copyright Carbon Black 2013 All Rights Reserved</td>
      </tr>
    </table>
  </body>
</html>
'''

binary_template = '''
<html>
  <head>
    <title>Carbon Black {{integration_name}} Feed</title>

    <style type="text/css">
    A:link {color: black;}
    A:visited {color: black;}
    A:active {color: black;}
    A:hover {underline; color: #d02828;}
    </style>

    <style>
    #config
    {
    font-family:"Trebuchet MS", Arial, Helvetica, sans-serif;
    width:100%;
    border-collapse:collapse;
    }
    #config td, #config th
    {
    font-size:1em;
    border:1px solid #000000;
    padding:3px 7px 2px 7px;
    }
    #config th
    {
    font-size:1.1em;
    text-align:left;
    padding-top:5px;
    padding-bottom:4px;
    background-color:#d02828;
    color:#ffffff;
    }
    #config tr.alt td
    {
    color:#000000;
    background-color:#666666;
    }
    </style>
  </head>
  <body bgcolor='white'>
    <table align='center'>
      <tr>
        <td>
          <h3>
            Feed Reports
          </h3>
          <table id="config" align='center'>
            <tr>
               <th><b>MD5sum</b></td>
               <th><b>Short Result</b></td>
               <th><b>Long Result</b></td>
               <th><b>Score</b></td>
            </tr>
            {% for binary in binaries %}
            <tr class={{loop.cycle('', 'alt')}}>
              <td>{{binary['md5sum']}}</td>
              <td>{{binary['short_result']}}</td>
              <td>{{binary['detailed_result']}}</td>
              <td>{{binary['score']}}</td>
            </tr>
            {% endfor %}
          </table>
          <br>
      <tr>
        <td>Copyright Carbon Black 2015 All Rights Reserved</td>
      </tr>
    </table>
  </body>
</html>
'''
