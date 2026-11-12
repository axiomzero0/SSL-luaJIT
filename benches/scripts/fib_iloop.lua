-- iterative Fibonacci pair walk with multiple assignment: 2,000,000 iterations
-- values widen from integer to double around i=90 on both VMs (dual-number model)
local a, b = 0, 1
for i = 1, 2000000 do
  a, b = b, a + b
end
print(a)
