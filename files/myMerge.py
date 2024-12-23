"""
Merge the current data with the defaults.
Supports entries with +value or -value 
"""
def myMerge(old, inparm):
    """
    Main routine to merge
    """

    delta = 0
    element = 0
    newlist = old
    #print("==6",inparm)
    if isinstance(inparm,str):
        val = [inparm]
    elif isinstance(inparm,list):
        val  = inparm
    else:
        print("==line12",type(inparm),inparm)
        raise ValueError("Unexpected data type "+ type(inparm))
    #print("---line14",in)
    for w in val:
        if isinstance(w,dict):
            element +=  1
        else:
        # print(type(w),w)
            if w.startswith('+'):
                delta += 1
            elif w.startswith('-'):
                delta += 1
            else :
                element +=  1

    if (delta > 0 and element > 0)  :
        print("delta",delta,"element",element)
        raise ValueError("Invalid data, it has mixed types, delta and specific")

    if element > 0 :  # only a list
        return inparm
    # we only have + or -
    for w in val:
        if w.startswith('+'):
            print("--34",w )
            newlist.append(w[1:])
        else:
            w2 = w[1:]
            if w2 in newlist:
                newlist.remove(w2)
    return newlist
