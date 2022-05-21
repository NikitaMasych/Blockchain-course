import platform, time

POSSIBLE_VALUES = (8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096)
    
def getCardinality():
    bit_width = int(input("Enter the length of bit sequence: "))
    assert bit_width in POSSIBLE_VALUES, "Invalid value!" 
    return bit_width

def calculateKeySpace(bit_width):
    return 2 ** bit_width # combinatorics | multiply rule

def calculateAllSpace():
    ranges = [calculateKeySpace(i) for i in POSSIBLE_VALUES]
    return ranges

def keyGenerator():
    """
        Determines python version and if it is greater or equal 3.6 
        uses secrets module, overwise - random (which is less secure)
    """
    configuration = int("".join(platform.python_version().split('.'))) # obtains python version
    
    f = __import__('secrets').randbits if configuration >= 360 else __import__('random').getrandbits 

    result = {x:f(x) for x in POSSIBLE_VALUES}

    return result

def getAnswer(subject):
    ans = input("Would you like to see {}? (yes/no): ".format(subject)).lower()
    assert ans in {'yes', 'no'}, "Invalid option!"
    return ans

def outputRanges(ranges):
    for index, space in enumerate(ranges):
        print("For {} bool function cardinality range is: {}".format(index, space), end='\n')

def outputKeys(database):
    print("Generation result:", end='\n')
    for width, key in database.items():
        print("{0:4d} : 0x{1:0{2}x}".format(width, key, width // 4), end='\n') 
        # width // 4 implements correct leading zeros output

def brutForce(database, ranges):
    # wanna cry from it's complexity 🥺
    counter = 0
    for key in database.values():
        start_time = time.time()
        for i in range(ranges[counter]):
            if i == key:
                print("Key {} found! Estimating time: {}".format(counter+1, (time.time()-start_time)*1000))
                    # multiply by 1000 in order to get time in milliseconds
        counter += 1

if __name__ == '__main__':
    while(True):
        try:
            bit_width = getCardinality()
            volume = calculateKeySpace(bit_width)
            print("For the given length of bit sequence keyspace is:", volume)
            ranges = calculateAllSpace()

            if getAnswer("all ranges") == 'yes':
                outputRanges(ranges)
            else:
                print("Understandable, have a great day!")
            break
            
        except AssertionError as msg:
            print(msg)
        except Exception:
            print("Something went wrong!") #  :(  

    while(True):
        try:
            generated_keys = keyGenerator()
            if getAnswer("generated keys") == 'yes':
                outputKeys(generated_keys)
            else:
                print("Understandable, have a great day!")
            break
        except AssertionError as msg:
            print(msg)
        except Exception:
            print("Something went wrong!") #  :( 

    brutForce(generated_keys, ranges)
    