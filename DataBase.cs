using Microsoft.EntityFrameworkCore;

namespace MessageServer
{
    public class ApplicationContext : DbContext
    {
        public DbSet<Datacell> UserDB { get; set; } = null!;
        public DbSet<Message> MessageDB { get; set; } = null!;
        public DbSet<OperationConfurm> OperationConfurmTable { get; set; } = null!;
        public ApplicationContext(DbContextOptions<ApplicationContext> options)
            : base(options)
        {
            Database.EnsureCreated();   // создаем базу данных при первом обращении
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Datacell>();
            modelBuilder.Entity<Message>();
            modelBuilder.Entity<OperationConfurm>();
        }
    }
}