def quicksort (arr, method):
    if len(arr) <= 1:
        return arr
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]  
    right = [x for x in arr if x > pivot]
    if method=='A':
        return quicksort(left, method) + middle + quicksort(right, method)
    elif method=='D':
        return quicksort(right, method) + middle + quicksort(left, method)

Str = ''
method = input("-o :")
if method != 'A' and method !='D': 
    print("잘못된 입력으로 종료합니다.")
    exit(0)

arraytest= []
temparr = []
temparr = input("-i :")
flag = 1
    
if len(temparr) <= 0:
    print("Length가 0입니다.")
    exit(0)

if temparr[len(temparr) - 1] != ' ':
     temparr += ' '

for i in temparr :
    if ord(i) == 45 :
        flag = -1

    elif ord(i) != 32 :
        if ord(i)>57 or ord(i)<48:
            print("입력오류로 종료합니다.")
            exit(0)
        Str += i
        
    else :
        arraytest += [flag*int(Str)]
        Str = ''
        flag = 1
    
if len(arraytest) <= 0:
    print("Length가 0입니다.")
    exit(0)

print(quicksort(arraytest, method))