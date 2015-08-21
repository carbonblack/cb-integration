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
