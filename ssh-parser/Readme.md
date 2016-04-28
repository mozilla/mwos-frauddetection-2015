### Abstract
We propose a general approach to analyzing log files and implement a framework to detect SSH compromise with log files. Our approach divides the log analysis process into the three steps: parsing log, managing abstract data and building back-end analyzers. In the first step, the log files are parsed to the sequence of events, and all session information are identified and extracted. In the second phase, the parsed results are abstracted to a higher level and saved in the database. We provide database APIs to facilitate access to the information. They are used in the last step in making back-end detection modules. We provide three back-end modules: the analysis reporter, the rule-based detector, and the behavioral-based detector. We paired two techniques to detect compromise effectively. The rule-based detector finds the compromise by checking violation of given rules. The behavioral-based detector finds the compromise by detecting an anomaly in user behavior patterns. They are complementary and allow for automatically detecting suspicious accesses only using SSH log files. We have implemented our approach and applied the framework to real SSH logs. From the experiment, our framework provides useful analysis report which helps us understand more about the attacks, and finds some suspicious concurrent accesses from different locations.

![](https://cloud.githubusercontent.com/assets/14894590/14733123/27eac382-0826-11e6-8afc-6491647525b6.png)

### Motivation
We paid attention to SSH log files. SSH log files exist in almost every SSH server and are accumulated all the time. However, there are less research to exploit these log files, and it is also difficult for administrators to audit the log manually. Therefore, they usually end up occupying spaces uselessly. our goal is to exploit those SSH log files and provide practical solution to detect SSH attack and compromise.

### What Our Framework Provides
* `Analysis reporter` provides general statistics about users, access IP addresses with detail location and attack statistics such as how many attack happened, where they are mostly from and so on.
* `Rule-baed detector` provides warning messages after checking any violation against security rules.
* `Behavioral-based detector` find any anomaly from the user behavior patterns.

### Usage

#### Parsing SSH log file
It extract all ssh streams by identifying and combining related log messages from connection event to disconnection event. If it suceeds, it yields the csv file that has all session information.

```bash
ssh_stream_extractor.py <SSH log file>
```

#### Log2DB
It populates DB Tables from the stream file that is output of `ssh_stream_extractor.py`

```bash
java -cp \"mysql-connector-java-5.1.38-bin.jar:.\" -Djava.library.path=. Log2DB <StreamFile> dbname hostip port"
```

#### IP Crawler
Reading IP Table in DB, it gathers more IP information like country, city, ISP from the www.iplocation.net and generates the output cvs file.

```bash
IpDBCrawler.py <host> <DBName> <DB Username>
    ex) IpDBCrawler.py localhost anomalyDatabase testUser
```

#### DB Commander
It provides essential commands that fill database with addtional information with AttackInformation and IP.

```
java -cp \"mysql-connector-java-5.1.38-bin.jar:.\" -Djava.library.path=. DBApi dbname hostip port <option> [argment]
    option)
        -a            // calculate attack and show them
        -ia           // calculate attack and insert them to DB
        -ii <ip_file> // get csv file for IP info inser them to DB
        -b <TERM>     // calculate all behaviroal feature and save the file
    <ip_file>   CSV file containing ip address information
    <TERM>      D, W, M, E     // Day, Week, Month, each login time
```

#### Analysis Reproter
```
java -cp \"mysql-connector-java-5.1.38-bin.jar:.\" -Djava.library.path=. AnalysisReporter dbname hostip port
```

#### Rule-base Detector
```
java -cp \"mysql-connector-java-5.1.38-bin.jar:.\" -Djava.library.path=. RuleDetector dbname hostip port
```

#### Feature extraction for Behavioral-base Detector
```
java -cp \"mysql-connector-java-5.1.38-bin.jar:.\" -Djava.library.path=. DBApi dbname hostip port -b D
```

#### Unique log identifier
You don't need to call unless you want to know SSH log frequncy and its types or find any bugs in our parser.
It gives all unique log messages and their frequency.

```bash
logIdentifier.py fileName [fileName]
```

### Example

#### DB API Usage
This simple example shows the checking code whether there has been the log-in from the "root" user.

```javascript
boolean isThereRootLogin(DBManager db)
{
  // select 'root' user from User table
  User rootUser = User.loadbyUsername(db, "root");
  if (rootUser != null){
    // select all history where user name is 'root'
    Vector<ConnectionHistory> historyList = ConnectionHistory.loadByUser(db, rootUser);

    for (ConnectionHistory history : historyList){
      if(history.isSuccessfulLogin == true){
          // found!
        return true;
      }
    }
  }
  return false;
}
```

#### Rule-base Detection Example
![](https://cloud.githubusercontent.com/assets/14894590/14700604/40817b86-0766-11e6-8622-df96d7aeb71e.png)


#### Feature extraction Example
![](https://cloud.githubusercontent.com/assets/14894590/14700728/19b59252-0767-11e6-90c6-e1c941e7405d.png)

## Progress Update
* Update: (3/30/16)
  - We implemented python scripts that identifies the unique log pattern and we analyzed the log pattern manually and found which one is interesting.
* Update: (4/8/16)
  - We implemented python scripts that parses the log files and extract ssh streams by identifying and combining related log messages from connection event to disconnection event.
  - From the extract ssh stream, we run our ML algorithm and got some data.
* Update: (4/14/16):
  - We designed DB schema and implemented DB APIs using Java and put all our stream data to DB.
  - We populated DB with two real SSH log data; one's event number is 185,840 and anther one is 645,855.
  - We are implementing rule base detector and ML base detector using DB data.
* Update: (4/20/16):
  - We finished rule based detector.
  - We finished experiments and got some data.
