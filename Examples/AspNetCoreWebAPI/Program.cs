WebApplication.CreateBuilder(args)
    .TestApplicationServices()
    .Build()
    .TestApplicationSetup()
    .Run();