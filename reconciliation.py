"""
 Copyright (c) 2026 Fabio Campos

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """


import numpy as np
import matplotlib.pyplot as plt
import re
from sage.all import *
import random
import sys
import time
import argparse
from sage.doctest.util import Timer
from sage.misc.sage_timeit import SageTimeitResult

def init_globals():
    """Initialize all global variables for the UOV attack"""
    global v, m, n, q, fixed, K, F, R, x
    
    # number of vinegar variables
    v = 68
    # number of oil variables = number of public key equations in UOV
    m = 44
    # total number of variables
    n = m + v
    # field size q
    q = 256
    
    # constant needed for the KS attack
    fixed = 3*m - n
    
    # define the field that is used in UOV
    F = GF(2)['y']
    (y,) = F._first_ngens(1)
    K = GF(q, 'z', modulus=y**8 + y**4 + y**3 + y + 1, repr='int', proof=False, names=('z',))
    (z,) = K._first_ngens(1)
    
    # Define polynomial ring
    R = PolynomialRing(K, 'x', v, order='degrevlex')
    x = R.gens()
    
    return v, m, n, q, fixed, K, F, R, x


############################################
##### Kipnis-Shamir attack

def FindOilKipnisShamir(m, matrices_sym, matrices, var_change):
    R = PolynomialRing(K,'x', n, order='degrevlex')
    flag_found=True
    trial=0 
    while flag_found:
        M0=matrices_sym[0]
        M1=matrices_sym[1]
        flag_inv=True
        while flag_inv:
            for j in range(1,m):
                M0 += K.random_element()*matrices_sym[j]
                M1 += K.random_element()*matrices_sym[j]
            if M0.is_invertible():
                flag_inv=False
        M=M0.inverse()*M1
        pol= M.charpoly()
        P=pol.factor()
        for i in range(len(P)-1,-1,-1):
            P1=list(P)[i]
            PP=P1[0]
            PP_coef = list(PP) 
            I=identity_matrix(K, n-m-fixed)
            PP_M=PP_coef[0]*I
            for ii in range(1,len(PP_coef)):
                PP_M+=PP_coef[ii]*M**ii
            PP_M_Ker=PP_M.right_kernel()
            basis=PP_M_Ker.basis_matrix()
            check=Eval(matrices,Matrix(R,1,n-m-fixed,[basis[0,i] for i in range(n-m-fixed)]),Matrix(R,1,n-m-fixed,[basis[0,i] for i in range(n-m-fixed)]))
            flag1=0 
            for i in range(m):
                if check[i][0] == 0:
                    flag1+=1
            if flag1 == m:
                flag_found=False
                oil1=var_change*Matrix(K,n-m-fixed,1,[basis[0,i] for i in range(n-m-fixed)])
                break
        trial+=1
    return oil1.transpose()

#############################################
##### Prep for Kipnis-Shamir attack #################

# find the linear relations
def InitialLinSystemKS(a_full, PublicKeySymm, x, fixed):
    R = PolynomialRing(K,'x', n, order='degrevlex')
    systemM=[]
    system=[x[n-m-i] for i in range(fixed,0,-1)] 
    # linear equations
    systemM = Eval(PublicKeySymm,Matrix(R,1,n,a_full[0]), Matrix(R,1,n,a_full[1]))
    for j in range(len(systemM)):
        system+=systemM[j][0]
    Arev=LinearSystemToMatrixReversed(system,n,m+fixed)
    Areduced=Arev.echelon_form()
    xrev = x
    xrev.reverse()
    xrev_short = []
    for jj in range(m+fixed):
        xrev_short+=[xrev[jj]]
    partial_sol=Areduced*Matrix(R,n,1,xrev)+Matrix(R,m+fixed,1,xrev_short)
    x.reverse()
    full_sol=[x[i] for i in range(n-m-fixed)]+[partial_sol[i,0] for i in range(m-1+fixed,-1,-1)]
    return full_sol

# find matrix form of linear system in reversed order
def LinearSystemToMatrixReversed(system,n,m):
    R = PolynomialRing(K,'x', n, order='degrevlex')
    x = list(R.gens())
    A=Matrix(K,m,n)
    for i in range(len(system)):
        temp=system[i]
        coefs=temp.coefficients()
        monoms=temp.monomials()
        for j in range(n):
            for l in range(len(monoms)):
                if monoms[l] == x[j]:
                    A[i,n-j-1]=coefs[l]
    return A

# find matrix form of linear system
def LinearSystemToMatrix(system,n,m):
    R = PolynomialRing(K,'x', n, order='degrevlex')
    x = list(R.gens())	        
    A=Matrix(K,m,n)
    for i in range(len(system)):
        temp=system[i]
        coefs=temp.coefficients()
        monoms=temp.monomials()
        for j in range(n):
            for l in range(len(monoms)):
                if monoms[l] == x[j]:
                    A[i,j]=coefs[l]
    return A

# form the system 
def InitialSystemKS(a_full, PublicKey):
    systemM=[]
    system=[]
    for j in range(0,len(a_full)):
        systemM += Eval(PublicKey,Matrix(R,1,n,a_full[j]), Matrix(R,1,n,a_full[j]))
    for j in range(len(systemM)):
        system+=systemM[j][0]
    return system

# find coefficient matrices
def PolynomialToMatrix(system,k):
    R = PolynomialRing(K,'x', n, order='degrevlex')
    x = list(R.gens())
    system_matrices=[]
    system_matrices_sym=[]
    for i in range(len(system)):
        M=Matrix(K,k,k)
        temp=system[i]
        coefs=temp.coefficients()
        monoms=temp.monomials()
        for j1 in range(k):
            for j2 in range(j1,k):
                for l in range(len(monoms)):
                    if monoms[l] == x[j1]*x[j2]:
                        M[j1,j2]=coefs[l]
        system_matrices+=[M]
        system_matrices_sym+=[M+M.transpose()]
    return system_matrices, system_matrices_sym

# need to check check_vin function
def check_vin(vin,P,sig):
    oil = zero_vector(K,n)
    for i in range(n):
        if (i<v):
            oil[i] = sig[i] + vin[i]
        else:
            oil[i] = sig[i]
    # check evaluation
    eval = zero_vector(K,m)
    for i in range(m):
        eval[i]=oil*P[i]*oil   
        if (eval[i] != 0):
            print("BADDDDDD")
            return 0
    print("goooooooooood")
    return oil

def check_oil(oil_in,P):
    oil = zero_vector(K,n)
    for i in range(n):
            oil[i] = oil_in[i]
    # check evaluation
    eval = zero_vector(K,m)
    for i in range(m):          
        eval[i]=oil*P[i]*oil             
        if (eval[i] != 0):
            return 0
    return oil


def ReplaceWithSCAoil(a_full,recoveredOil):
    for i in range(len(recoveredOil)):
        a_full[i]=recoveredOil[i]

def readPK(path):
    with open(path, 'r') as file:
        input = file.read()
    pk = input.split(", ")

    # convert between types of key
    P1 = pk[:103224]
    P2 = pk[103224:234872]
    P3 = pk[234872:]
   
    len_old = [2992, 2948, 2904, 2860, 2816, 2772, 2728, 2684, 2640, 2596, 2552, 2508, 2464, 2420, 2376, 2332, 
               2288, 2244, 2200, 2156, 2112, 2068, 2024, 1980, 1936, 1892, 1848, 1804, 1760, 1716, 1672, 1628, 
               1584, 1540, 1496, 1452, 1408, 1364, 1320, 1276, 1232, 1188, 1144, 1100, 1056, 1012, 968, 924, 880, 
               836, 792, 748, 704, 660, 616, 572, 528, 484, 440, 396, 352, 308, 264, 220, 176, 132, 88, 44]
    
    interleaved = []
    summe = 0
    for i, x in enumerate(len_old):
        interleaved.append(P1[summe:summe+x])
        interleaved.append(P2[i*1936:(i+1)*1936])
        summe = summe + x

    interleaved.append(P3)

    # to flat the key
    pk = [x for sub in interleaved for x in sub]

    ######################################
    # sort PK to matrices                #
    ######################################
    P = [zero_matrix(K,n,n) for _ in range(m)]
    t = 0
    # sort P1array to matrices
    for i in range(n):
        for j in range (i,n):
            for k in range(m):
                P[k][i,j]=K(ZZ(int(pk[t],16)).digits(base=2))
                t = t+1         
    return P  

######################################
##### helper #########################

def SplitInto_k(L, k):
    l = len(L)
    m = l // k # the length of the sublists
    return [list(L[i*m:(i+1)*m]) for i in range(k)]

def AppendIndependent(L, k, first_index):
    l = len(L)
    aug_list = [[0 for j in range(k)]+L[i] for i in range(l)]
    for i in range(l):
        aug_list[i][i + first_index]=1
    return aug_list

# insert the found lin relations into the vectors		
def InsertLinEq(a_full,sol_full):
    temp = a_full[len(a_full)-1]
    for i in range(m,n):
        temp[i]=sol_full[i-m]
    a_full[len(a_full)-1] = temp

# insert the lin solutions in the list of vars to be used in the quad. system
def InsertFound(solution,vector_vars):
    for i in range(0,v-m):
        vector_vars[n-m-i-1] = solution[i]

# turn random matrix to upper diagonal
def RandomToUpper(M):
    n = M.ncols()
    retM = M
    for i in range(n):
        for j in range(i+1,n):
            retM[i,j] += retM[j,i]
            retM[j,i] = K(0) 
    return retM
            
# turn upper diagonal matrix to symmetric
def UpperToSymmetric(M):
    return M+M.transpose() 

# evaluate Multivariate map 
def Eval(F,x,y):
    return [ x*M*(y.transpose()) for M in F]

def Evalleft(F,x):
    return [ x*M for M in F]

#############################################
##### Reconciliation attack #################

# find the linear relations
def InitialLinSystem(a_full, PublicKeySymm, known):
    R = PolynomialRing(K,'x', v, order='degrevlex')
    systemM=[]
    # linear equations
    k = len(a_full)-1
    for j in range(len(a_full)-1):
        systemM += Evalleft(PublicKeySymm,Matrix(R,1,n,a_full[j]))
    A=Matrix(R,1,n,systemM[0])
    for i in range(1,len(systemM)):
        A=A.stack(vector(systemM[i])) 
    listvars=list([i for i in range(m,n)])
    listvars.reverse()
    Asmall = A[[i for i in range(len(systemM))],listvars+list([w])]
    reducedAsmall=Asmall.echelon_form()
    reversed_a_full=list([a_full[k][i] for i in range(m,n)])
    reversed_a_full.reverse()
    vector_vars=vector(reversed_a_full+list([a_full[k][w]]))
    partial_sol=reducedAsmall*vector_vars-vector([x[i] for i in range(v-1,v-m-1,-1)]) 
    full_sol=[x[i] for i in range(v-m)]+[partial_sol[i] for i in range(m-1,-1,-1)]
    return full_sol, reducedAsmall, vector_vars

# form the system 
def InitialSystem(a_full, PublicKey, PublicKeySymm, known):
    systemM=[]
    system=[]
    # linear equations
    for j in range(len(a_full)):
        for k in range(max(known,j+1),len(a_full)):
            systemM += Eval(PublicKeySymm,Matrix(R,1,n,a_full[j]), Matrix(R,1,n,a_full[k]))
    # quadratic equations
    for j in range(known,len(a_full)):
        systemM += Eval(PublicKey,Matrix(R,1,n,a_full[j]), Matrix(R,1,n,a_full[j]))
    for j in range(len(systemM)):
        system+=systemM[j][0]
    return system

# solve the system 
def SolveSystem(system, recoveredOil, w):
    I=ideal(system)
    gr=I.groebner_basis()

    solution_full=[]
    solution_split=[]
    temp_recoveredOil = recoveredOil
    if len(gr)==v:
        solution=[x[i]-gr[i] for i in range(v)]

        solution_split = SplitInto_k(solution, 1)
        solution_full=AppendIndependent(solution_split, m, w + found)
        temp_recoveredOil += solution_full

    else:
        print("NO oil vectors found")
        if len(gr)==1:
            print("Needs randomization")
        else:
            print("Needs more vectors")
    return solution_full,solution_split,temp_recoveredOil

def KipnisShamir(R, Oilspace, PK):
    print("starting InitialLinSystemKS ...")
    start = time.time()
    sol_full = InitialLinSystemKS([Oilspace] + [list(R.gens())], [UpperToSymmetric(j) for j in PK], list(R.gens()), fixed)
    print(f"Time: {time.time() - start:.2f}s")

    print("starting LinearSystemToMatrix ...")
    start = time.time()
    var_change = LinearSystemToMatrix(sol_full,n-m-fixed,n)
    print(f"Time: {time.time() - start:.2f}s")

    print("starting InitialSystemKS ...")
    start = time.time()
    system = InitialSystemKS([sol_full], PK)
    print(f"Time: {time.time() - start:.2f}s")

    print("starting PolynomialToMatrix ...")
    start = time.time()
    matrices, matrices_sym=PolynomialToMatrix(system,n-m-fixed)
    print(f"Time: {time.time() - start:.2f}s")

    print("starting FindOilKipnisShamir ...")
    start = time.time()    
    foundoil = FindOilKipnisShamir(m, matrices_sym, matrices, var_change)
    print(f"Time: {time.time() - start:.2f}s")

    Oilspace = [Oilspace] + [[foundoil[0][i] for i in range(n)]]

    return Oilspace

def load_hex_data(input_str):
    """Load hex data from file or direct hex string"""
    # Check if input is a file path
    if len(input_str) < 200 and ('/' in input_str or '\\' in input_str or input_str.endswith('.txt')):
        try:
            with open(input_str, 'r') as f:
                hex_data = f.read().strip()
        except FileNotFoundError:
            print(f"Error: File not found: {input_str}")
            sys.exit(1)
    else:
        # Assume it's a hex string
        hex_data = input_str.strip()
    
    # Remove any whitespace or newlines
    hex_data = ''.join(hex_data.split())
    
    # Convert hex to list of field elements
    try:
        data = list(bytes.fromhex(hex_data))
        data = [K(ZZ(x).digits(base=2)) for x in data]
    except ValueError as e:
        print(f"Error: Invalid hex data: {e}")
        sys.exit(1)
    
    return data


def main(pk_path, oil_hex):
    """
    Main function to run UOV attack
    
    Args:
        pk_path: Path to public key file
        oil_hex: Oil vector ~ faulty signature as hex string
    
    Returns:
        Recovered oil space basis
    """

    global v, m, n, q, fixed, K, F, R, x, found, w
    
    # Initialize global variables
    v, m, n, q, fixed, K, F, R, x = init_globals()
    
    # Load OIL vector
    print(f"Loading faulty signature ...")
    OIL = load_hex_data(oil_hex)

    # Load public key
    print(f"Loading public key from: {args.pk}")
    PK = readPK(args.pk)    
    
    # optional validation
    Oilspace = check_oil(OIL, PK)
    if Oilspace == 0:
        print("ERROR: Invalid oil vector")
        return None
    print("Oil vector verified successfully!")

    R = PolynomialRing(K,'x', n, order='degrevlex')

    # Kipnis-Shamir attack
    Oilspace = KipnisShamir(R, Oilspace, PK)

    w = 2
    found = 0

    # start the reconciliation part
    x = R.gens()

    a=SplitInto_k([x[i] for i in range(v)], 1)

    solution_split=[[Oilspace[0][i] for i in range(m,n)],[Oilspace[1][i] for i in range(m,n)]]

    print("starting loop ...")
    count = 0
    while found < m-w:
        a_aug = solution_split + a

        print(str(count) + " starting SolveSystem ...")
        start = time.time()
        a_full=AppendIndependent(a_aug, m, 0)
        ReplaceWithSCAoil(a_full,Oilspace)
        system = InitialSystem(a_full, PK, [UpperToSymmetric(j) for j in PK],w+found)
        solution_full,solution_split_found,Oilspace = SolveSystem(system, Oilspace, w)
        print(f"Time: {time.time() - start:.2f}s")    

        count = count + 1
        solution_split += solution_split_found
        
        found += len(solution_full)
    
    print('\nThe following is a basis of the secret Oilspace.\n')
    # Convert Oilspace entries from polynomial to integer representation for output
    for i in range(w,m):
        for j in range(m,n):
            if not (Oilspace[i][j].coefficients()):
                Oilspace[i][j] = 0
            else:
                Oilspace[i][j] = Oilspace[i][j].coefficients()[0]        
    
    for i in range(m):    
        print(Oilspace[i])   

    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='UOV Key Recovery Attack')
    parser.add_argument('--pk', required=True, help='Path to public key file')
    parser.add_argument('--oil', required=True, help='Oil vector ~ faulty signature (hex string)')

    args = parser.parse_args()
    
    startTime = time.time()
    result = main(args.pk, args.oil)    
    endTime = time.time()

    if result:
        print("\nAttack successful!")       
    else:
        print("\nAttack failed!")

    print(f"Total execution time:  {endTime - startTime:.2f}s")         