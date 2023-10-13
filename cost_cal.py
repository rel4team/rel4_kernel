import re

baseline_file = "./baseline.txt"
rel4_file = "./rel4.txt"
def get_res(file_path):
    res = {}
    with open(file_path , 'r') as file:
        for line in file:
            matches = re.findall(r'test_name: (.*?), Test cost: (\d+)', line)
            for match in matches:
                test_name, test_cost = match
                res[test_name] = int(test_cost)
    return res

if __name__ == "__main__":
    rel4_res = get_res(rel4_file)
    baseline_res = get_res(baseline_file)
    diff = {}
    for test_name in rel4_res:
        diff[test_name] = 1 - (baseline_res[test_name] / rel4_res[test_name])
        print("test_name: " + test_name + ", diff: " + str(diff[test_name]))
    