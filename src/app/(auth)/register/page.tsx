import RegisterForm from "@/client/auth/components/RegisterForm";

export default function RegisterPage() {
  return (
    <div className="min-h-screen flex items-stretch bg-[#0F0F0F] font-gothic">
      <div className="hidden lg:block w-1/2 relative overflow-hidden h-screen">
        <img
          src="https://i.pinimg.com/736x/f6/60/fd/f660fdc0be1bc9faa08799fe28424dae.jpg"
          alt="Register visual"
          className="w-full h-full object-cover"
        />
        <div className="absolute inset-0 bg-black/30" />
      </div>

      <div className="w-full lg:w-1/2 flex flex-col items-center justify-between px-8 py-12 h-screen">
        <div />

        <div className="w-full max-w-md text-white">
          <RegisterForm />
        </div>

        <div className="w-full max-w-md">
          <div className="border-t border-white/5 pt-4">
            <h2 className="text-[12px] text-white/30 mb-1">
              Terms & Conditions
            </h2>
            <p className="text-[11px] text-neutral-600 leading-relaxed">
              By accessing this website, you agree to follow all applicable laws
              and our terms of service.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
