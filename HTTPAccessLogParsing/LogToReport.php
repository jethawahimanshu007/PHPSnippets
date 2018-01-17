<!--This file generates reports based on HTTP Access Log using PHP-->
<html>

<form action="<?php $_PHP_SELF ?>" method="POST">
Enter Log Path:<br>
<input type="text" name="logPath" value=""><br>
Enter Report Path:<br>
<input type="text" name="reportPath" value=""><br>
<input type='submit'> <br>
</form>

<!--Main application logic-->
<?php
if(!array_key_exists('logPath',$_POST) || !array_key_exists('reportPath',$_POST))
exit();
else {
  $logFile=$_POST['logPath'];
  $reportPath=$_POST['reportPath'];
}
//Initialize variables
//Vars
$noOfEntries=0;$noOfErrors=0;$noOfSuccess=0;

//Arrays
$filesVisited=[];$referrersList=[];$userAgentBrowsers=[];$userAgentPlatforms=[];

//File paths
//$logFile="C:\wamp64\logs\accessCopy.log";
//$reportPath="C:\wamp64\logs\HTTPAnalysisReport.txt";

//Open the file
$fileHandler=fopen($logFile,"r") or die("Unable to open file!");

//Go through the file line by line
while(!feof($fileHandler))
{
  $lineInConcern=fgets($fileHandler);

  /*Part 1 - Find no of entries in the log file*/
  $noOfEntries++;


  /*Part 2- Find the success and error rates*/
  /*Example LogFile Entry-- 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"*/
  //Splitting the String on " as most of the info we require can be accessed easily doing that!
  $regExSplit=preg_split("/\"/", $lineInConcern);

  //Splitting the SplitString[2] on space will give Status code easily
  $statusCode=preg_split("/\s/",$regExSplit[2])[1];
  if(preg_match("/^2/",$statusCode))
  $noOfSuccess++;
  else if(preg_match("/^2/",$statusCode))
  $noOfErrors++;


  /*Part 3- Find the files most often visited*/
  //Splitting the SplitString[1] on space will give visited file easily-- Note: if file names might have space in them,
  //the string should be split once again or another regex can be used!
  $fileVisited=preg_split("/\s/",$regExSplit[1])[1];
  //Add to array if the file is not added before
  $filesVisited=putInArray($fileVisited,$filesVisited);


  /*Part 4- Find most popular referrers*/
  $referrer=$regExSplit[3];
  //Add to array if the user agent is not added before
  $referrersList=putInArray($referrer,$referrersList);


  /*Part 5- Find top user agents*/
  $user_agent=parseUserAgent($regExSplit[5]);
  $userAgentBrowsers=putInArray($user_agent['name'],$userAgentBrowsers);
  $userAgentPlatforms=putInArray($user_agent['platform'],$userAgentPlatforms);

}
fclose($fileHandler);

//Sort arrays in descending order of values
arsort($filesVisited);
arsort($referrersList);
arsort($userAgentBrowsers);
arsort($userAgentPlatforms);



//Begin writing to the file here:
$reportFile=fopen($reportPath,"w") or die("Can't create/write file");

//Part 1
fwrite($reportFile,"Total Entries:".$noOfEntries."\r\n\r\n"); //Part 1

//Part 2
$successPercent=$noOfSuccess/($noOfSuccess+$noOfErrors)*100;
fwrite($reportFile,"Successful requests no and %:   ".$noOfSuccess."(".$successPercent."%)"."\r\n\r\n");

//Part 3
$errorPercent=$noOfErrors/($noOfSuccess+$noOfErrors)*100;
fwrite($reportFile,"Unsuccessful requests no and %:   ".$noOfErrors."(".$errorPercent."%)"."\r\n\r\n");

//Part 4
fwrite($reportFile,"Most visited files in the descending order (no and %) in the following format  :\r\n");
fwrite($reportFile,"file    no    %\r\n");
printArrayToFile($filesVisited,$reportFile);
fwrite($reportFile,"\r\n\r\n");

//Part 5
fwrite($reportFile,"Most popular referrers in the descending order (no and %) in the following format  :\r\n");
fwrite($reportFile,"file    no    %\r\n");
printArrayToFile($referrersList,$reportFile);
fwrite($reportFile,"\r\n\r\n");

//Part 6
fwrite($reportFile,"Most user agent browsers used in the descending order (no and %) in the following format  :\r\n");
fwrite($reportFile,"Browser    no    %\r\n\r\n");
printArrayToFile($userAgentBrowsers,$reportFile);
fwrite($reportFile,"\r\n\r\n");

//Part 7
fwrite($reportFile,"Most user agent OS used in the descending order (no and %) in the following format  :\r\n");
fwrite($reportFile,"Browser    no    %\r\n\r\n");
printArrayToFile($userAgentPlatforms,$reportFile);
fwrite($reportFile,"\r\n\r\n");

fclose($reportFile);

echo "<script>alert('The report has been generated, please check the path: $reportPath!');</script>";
$_POST=array();
 ?>


<!--Functions for handling data-->
<?php
//Puts in array key value pairs, if key is not present ==> 1, otherwise value+1
function putInArray($arrayIndex,$arrayActual)
{
  //Add to array if the file is not added before
  if(!array_key_exists($arrayIndex,$arrayActual))
  $arrayActual[$arrayIndex]=1;
  else $arrayActual[$arrayIndex]+=1;
  return $arrayActual;
}

//Print array to file in format name:value:%
function printArrayToFile($arrayActual,$fileToWrite)
{
  $sizeOfArray=sizeof($arrayActual);
  $sumOfAll=0;
  foreach ($arrayActual as $key => $value) {
    $sumOfAll+=$value;
      }

  foreach ($arrayActual as $key => $value) {
      $percentVisit=$value/($sumOfAll)*100;
      fwrite($fileToWrite,"$key    $value    $percentVisit\r\n"); //Part 4
  }
}

function parseUserAgent($u_agent) {
            $bname = 'Unknown';
            $platform = 'Unknown';
            $version = "";
            $ub="";

            //First get the platform
            if (preg_match('/linux/i', $u_agent)) {
               $platform = 'Linux';
            }elseif (preg_match('/macintosh|mac os x/i', $u_agent)) {
               $platform = 'Mac';
            }elseif (preg_match('/windows|win/i', $u_agent)) {
               $platform = 'Windows';
            }

            // Next get the name of the useragent seperately
            if(preg_match('/MSIE/i',$u_agent) && !preg_match('/Opera/i',$u_agent)) {
               $bname = 'Internet Explorer';
               $ub = "MSIE";
            } elseif(preg_match('/Mozilla|Firefox/i',$u_agent)) {
               $bname = 'Mozilla Firefox';
               $ub = "Firefox";
            } elseif(preg_match('/Chrome/i',$u_agent)) {
               $bname = 'Google Chrome';
               $ub = "Chrome";
            }elseif(preg_match('/Safari/i',$u_agent)) {
               $bname = 'Apple Safari';
               $ub = "Safari";
            }elseif(preg_match('/Opera/i',$u_agent)) {
               $bname = 'Opera';
               $ub = "Opera";
            }elseif(preg_match('/Netscape/i',$u_agent)) {
               $bname = 'Netscape';
               $ub = "Netscape";
            }
            return array(
               'userAgent' => $u_agent,
               'name'      => $bname,
               'platform'  => $platform
            );
         }
 ?>



</html>
