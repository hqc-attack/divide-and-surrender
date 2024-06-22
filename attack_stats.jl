using DataFrames, CSV, Statistics

df = CSV.File("data/smt.csv") |> DataFrame

println("Performed $(size(df)[1]) attacks.")

success_rate = sum(df.wrong_zeros_x .+ df.wrong_zeros_y .== 0 .&& df.recovered_zeros_x .+ df.recovered_zeros_y .>= df.key_bits .+ 5) / size(df)[1] * 100
println("With a success rate of $(success_rate)%.")
println("A median of $(median(df.traces)) DIV-SMT traces were used to form responses to a median of $(median(df.queries)) oracle calls in a median attack runtime of $(median(df.duration_seconds)) seconds.")
println("The number of traces includes a median of $(median(df.calibration_traces)) calibration traces.")
