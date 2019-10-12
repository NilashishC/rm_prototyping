
def all_perms(elements):
    res = []
    for n in range(1, len(elements) + 1):
        res.extend(combinations(n, elements))
    return res

def combinations(N, iterable):
    if not N:
        return [[]]
    if not iterable:
        return []
    head = [iterable[0]]
    tail = iterable[1:]
    new_comb = [head + list_ for list_ in combinations(N - 1, tail) ]
    return new_comb + combinations(N, tail)
#
class FilterModule(object):
    """ Network interface filter """

    def filters(self):
        return {"all_perms": all_perms}
